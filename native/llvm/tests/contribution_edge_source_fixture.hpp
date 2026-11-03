#pragma once

#include "contribution_edges.hpp"
#include "cfg_origin.hpp"
#include "switch_lower_edges.hpp"
#include "hybrid_eh.hpp"

#include <memory>

#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff::test {
struct EdgeSourceFixture {
    llvm::LLVMContext context;
    llvm::Module module{"contribution-edge-source", context};
    llvm::Function *owner;
    llvm::BasicBlock *entry, *switched, *left, *right;
    CfgOrigins origins;
    ResolvedRecipe recipe;
    std::unique_ptr<ContributionEdgePlan> plan;
    HybridEhPlan eh;
    llvm::InvokeInst *invocation = nullptr;
    bool hybrid;

    explicit EdgeSourceFixture(unsigned seed = 17, bool with_hybrid = false, bool value_invoke = false,
        bool deferred = false) : hybrid(with_hybrid) {
        llvm::IRBuilder<> b(context);
        owner = llvm::Function::Create(llvm::FunctionType::get(b.getInt32Ty(), {b.getPtrTy(), b.getInt32Ty()}, false),
            llvm::Function::ExternalLinkage, "edge_source", module);
        const auto block = [&](const char *name) { return llvm::BasicBlock::Create(context, name, owner); };
        entry = block("entry"); switched = block("switch"); left = block("left"); right = block("right");
        llvm::BasicBlock *invoked = nullptr, *pad = nullptr, *cleanup = nullptr;
        llvm::AllocaInst *saved = nullptr;
        auto *exception_type = llvm::StructType::get(context, {b.getPtrTy(), b.getInt32Ty()});
        if (hybrid) {
            module.setTargetTriple(llvm::Triple("x86_64-w64-windows-gnu"));
            auto *personality = llvm::Function::Create(llvm::FunctionType::get(b.getInt32Ty(), true),
                llvm::Function::ExternalLinkage, "__gxx_personality_seh0", module);
            owner->setPersonalityFn(personality);
            invoked = block("invoked"); pad = block("pad"); cleanup = block("cleanup");
            b.SetInsertPoint(entry); saved = b.CreateAlloca(exception_type);
        }
        auto marker = module.getOrInsertFunction("pyobf_native_contribution_site_v1",
            llvm::FunctionType::get(b.getVoidTy(), {b.getPtrTy(), b.getInt32Ty()}, false));
        b.SetInsertPoint(entry); b.CreateCall(marker, {owner->getArg(0), b.getInt32(101)})->setDoesNotThrow();
        b.CreateCondBr(b.CreateICmpSLT(owner->getArg(1), b.getInt32(0)), switched, hybrid ? invoked : right);
        b.SetInsertPoint(switched); auto *branch = b.CreateSwitch(owner->getArg(1), right, 2);
        branch->addCase(b.getInt32(1), left); branch->addCase(b.getInt32(2), left);
        b.SetInsertPoint(left); auto *phi = b.CreatePHI(b.getInt32Ty(), 2);
        phi->addIncoming(b.getInt32(7), switched); phi->addIncoming(b.getInt32(7), switched);
        b.CreateBr(right);
        b.SetInsertPoint(right); b.CreateRet(b.getInt32(0));
        if (hybrid) {
            auto *target = llvm::Function::Create(llvm::FunctionType::get(value_invoke ? b.getInt32Ty() : b.getVoidTy(), false),
                llvm::Function::ExternalLinkage, "target", module);
            b.SetInsertPoint(invoked); invocation = b.CreateInvoke(target, right, pad, {});
            b.SetInsertPoint(pad); auto *exception = b.CreateLandingPad(exception_type, 0); exception->setCleanup(true);
            b.CreateStore(exception, saved); b.CreateBr(cleanup);
            b.SetInsertPoint(cleanup); b.CreateResume(b.CreateLoad(exception_type, saved));
            recipe.coverage = "hybrid-eh";
        }
        recipe.seeds["runtime-contribution"] = seed;
        if (deferred) recipe.components["deduplicate-blocks"] = Requirement::optional;
        recipe.contribution_options.selection = ContributionSelection::original_edges;
        plan = std::make_unique<ContributionEdgePlan>(*owner, recipe);
        if (!plan->failure().empty()) llvm::report_fatal_error(llvm::StringRef(plan->failure()));
        if (!deferred) plan->instrument(*owner, origins);
    }

    void lower() {
        if (hybrid) eh = prepare_hybrid_eh_edges(*owner, origins, plan.get());
        if (const auto reason = plan->before_lowering(*owner); !reason.empty()) llvm::report_fatal_error(llvm::StringRef(reason));
        lower_switch_edges(*owner, &origins, plan.get());
        // This fixture isolates source-routing proof. Executable tests separately run
        // the production acquisition adapter and its complete query/transition proof.
        llvm::IRBuilder<> b(context);
        auto query = module.getOrInsertFunction("pyobf_native_contribution_word_v1",
            llvm::FunctionType::get(b.getInt32Ty(), {b.getPtrTy(), b.getInt32Ty(), b.getInt32Ty(), b.getInt32Ty(),
                b.getInt32Ty(), b.getInt32Ty(), b.getInt32Ty()}, false));
        for (const auto &edge : plan->edges()) {
            auto *gateway = llvm::cast<llvm::BasicBlock>(edge.gateway);
            auto *marker = llvm::cast<llvm::CallInst>(&gateway->front()); b.SetInsertPoint(marker);
            auto *call = b.CreateCall(query, {owner->getArg(0), b.getInt32(7), b.getInt32(11), b.getInt32(13),
                b.getInt32(edge.label), b.getInt32(17), b.getInt32(0)});
            call->setMetadata("pyobf.contribution.query", llvm::MDNode::get(context, {}));
            marker->eraseFromParent();
        }
    }

    llvm::BasicBlock *gateway(unsigned index) { return llvm::cast<llvm::BasicBlock>(plan->edges()[index].gateway); }
    llvm::AllocaInst *slot() {
        for (auto &instruction : *entry) if (auto *value = llvm::dyn_cast<llvm::AllocaInst>(&instruction)) return value;
        llvm::report_fatal_error("switch fixture lost its condition slot");
    }
    llvm::BranchInst *first_case() {
        return llvm::cast<llvm::BranchInst>(llvm::cast<llvm::BranchInst>(switched->getTerminator())->getSuccessor(0)->getTerminator());
    }
};
}
