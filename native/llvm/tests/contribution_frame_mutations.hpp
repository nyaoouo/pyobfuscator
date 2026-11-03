#pragma once

#include "contribution_edge_source_fixture.hpp"

#include <functional>

#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {
struct FramedSourceFixture : EdgeSourceFixture {
    llvm::BasicBlock *completion;
    llvm::BasicBlock *normal;
    llvm::AllocaInst *frame;
    llvm::Function *helper;
    llvm::LoadInst *result;
    explicit FramedSourceFixture(unsigned seed = 17, bool notify = true, unsigned rejected_route = 0, bool deferred = false)
        : EdgeSourceFixture(seed, true, true, deferred) {
        auto *original = invocation;
        normal = original->getNormalDest();
        llvm::IRBuilder<> b(&*entry->getFirstInsertionPt()); frame = b.CreateAlloca(b.getInt32Ty());
        helper = llvm::Function::Create(llvm::FunctionType::get(b.getVoidTy(), {b.getPtrTy()}, false),
            llvm::Function::ExternalLinkage, "frame_helper", module);
        auto *helper_body = llvm::BasicBlock::Create(context, "entry", helper);
        b.SetInsertPoint(helper_body); b.CreateStore(b.getInt32(17), helper->getArg(0)); b.CreateRetVoid();
        completion = llvm::BasicBlock::Create(context, "frame.complete", owner, normal);
        b.SetInsertPoint(completion); result = b.CreateLoad(b.getInt32Ty(), frame); b.CreateBr(normal);
        b.SetInsertPoint(original);
        invocation = b.CreateInvoke(helper, completion, original->getUnwindDest(), {frame});
        if (rejected_route == 1) llvm::cast<llvm::BranchInst>(completion->getTerminator())->setSuccessor(0, right);
        if (rejected_route == 2) {
            auto *pad = llvm::BasicBlock::Create(context, "other.pad", owner);
            b.SetInsertPoint(pad);
            auto *exception = b.CreateLandingPad(llvm::StructType::get(context, {b.getPtrTy(), b.getInt32Ty()}), 0);
            exception->setCleanup(true); b.CreateResume(exception); invocation->setUnwindDest(pad);
        }
        if (rejected_route == 3) {
            completion->getTerminator()->eraseFromParent(); b.SetInsertPoint(completion);
            b.CreateCondBr(b.CreateICmpEQ(owner->getArg(1), b.getInt32(0)), normal, normal);
        }
        if (notify) {
            const auto error = plan->replace_invoke(rejected_route == 4 ? *invocation : *original, *invocation, *completion);
            if (error.empty() != (rejected_route == 0))
                llvm::report_fatal_error("framed source registration accepted a changed route or rejected its legal route");
        }
        original->replaceAllUsesWith(result);
        // Assert the precise historical regression, rather than infer it from a crash.
        for (const auto &edge : plan->edges()) if (edge.origin == original)
            if (static_cast<llvm::Value *>(edge.terminator) != (notify && rejected_route == 0 ? static_cast<llvm::Value *>(invocation) : result))
                llvm::report_fatal_error("invoke handle did not expose its registered/RAUW identity");
        original->eraseFromParent();
    }
    llvm::BasicBlock *split(bool notify) {
        auto *suffix = completion->splitBasicBlock(completion->getTerminator(), "frame.tail");
        if (notify) if (const auto error = plan->completion_split(*completion, *suffix); !error.empty())
            llvm::report_fatal_error(llvm::StringRef(error));
        return suffix;
    }
};
inline bool check_framed_sources() {
    for (bool deferred : {false, true}) for (unsigned seed : {1, 17, 41}) for (bool split : {false, true}) {
        FramedSourceFixture f(seed, true, 0, deferred); if (split) f.split(true);
        if (deferred) f.plan->instrument(*f.owner, f.origins);
        f.lower();
        const auto report = f.plan->report(false);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.plan->verify_sources(*f.owner).empty() ||
                report.getInteger("original_edges") != 8 || report.getInteger("excluded_unwind_edges") != 1) return false;
    }
    {
        FramedSourceFixture f(17, false);
        f.eh = prepare_hybrid_eh_edges(*f.owner, f.origins, f.plan.get());
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.plan->before_lowering(*f.owner).empty()) return false;
    }
    for (unsigned route : {1, 2, 3, 4}) {
        FramedSourceFixture f(17, true, route);
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.plan->before_lowering(*f.owner).empty()) return false;
    }
    const std::pair<const char *, std::function<void(FramedSourceFixture &)>> mutations[]{
        {"completion bypass", [](auto &f) { llvm::cast<llvm::BranchInst>(f.completion->getTerminator())->setSuccessor(0, f.right); }},
        {"wrong contribution", [](auto &f) { llvm::cast<llvm::BranchInst>(f.completion->getTerminator())->setSuccessor(0, f.gateway(0)); }},
        {"EH bridge bypasses completion", [](auto &f) { llvm::cast<llvm::BranchInst>(f.eh.invokes[0].gateway->getTerminator())->setSuccessor(0, f.normal); }},
        {"invoke bypasses EH bridge", [](auto &f) { f.invocation->setNormalDest(f.completion); }},
        {"unregistered completion split", [](auto &f) { f.split(false); }},
        {"registered split bypass", [](auto &f) { auto *tail = f.split(true); llvm::cast<llvm::BranchInst>(tail->getTerminator())->setSuccessor(0, f.right); }},
        {"split replay", [](auto &f) { auto *tail = f.split(true); f.plan->completion_split(*f.completion, *tail); }},
        {"replacement replay", [](auto &f) { f.plan->replace_invoke(*f.invocation, *f.invocation, *f.completion); }},
        {"lookalike completion RAUW", [](auto &f) {
            auto *other = llvm::BasicBlock::Create(f.context, "other.complete", f.owner);
            llvm::IRBuilder<>(other).CreateBr(f.normal); f.completion->replaceAllUsesWith(other);
        }},
        {"deleted completion", [](auto &f) { f.completion->replaceAllUsesWith(f.normal); f.completion->eraseFromParent(); }},
        {"source RAUW", [](auto &f) {
            auto *old = f.invocation; llvm::IRBuilder<> b(old);
            auto *other = b.CreateInvoke(f.helper, old->getNormalDest(), old->getUnwindDest(), {f.frame});
            old->replaceAllUsesWith(other); old->eraseFromParent(); f.invocation = other;
        }},
    };
    for (bool deferred : {false, true}) for (const auto &[name, mutate] : mutations) {
        FramedSourceFixture f(17, true, 0, deferred);
        if (deferred) f.plan->instrument(*f.owner, f.origins);
        f.lower(); mutate(f);
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.plan->verify_sources(*f.owner).empty()) {
            llvm::errs() << "framed contribution trace mutant escaped: " << name << "\n"; return false;
        }
    }
    llvm::outs() << "12 eager/deferred framed-source positives, preserved8 original normal edges/1 unwind exclusion,27 registration/trace/RAUW mutants verified\n";
    return true;
}
}
