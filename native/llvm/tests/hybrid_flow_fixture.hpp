#pragma once

#include "cff.hpp"
#include "hybrid_flow.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"
#include "transition_proof.hpp"

#include <memory>
#include <optional>

#include "llvm/TargetParser/Triple.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff::test {

struct HybridFixture {
    llvm::LLVMContext context;
    llvm::Module module{"hybrid-flow", context};
    llvm::Function *owner;
    llvm::BasicBlock *entry, *start, *a, *b, *gate_a, *gate_b, *returned, *pad, *cleanup, *dispatch;
    llvm::AllocaInst *state, *correction;
    llvm::StoreInst *initial;
    HybridEhPlan plan;
    StateLayout layout;
    std::unique_ptr<HybridFlowSeal> seal;

    explicit HybridFixture(unsigned seed = 17, std::optional<bool> fixed_condition = std::nullopt, unsigned return_width = 0) {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        module.setTargetTriple(llvm::Triple("x86_64-w64-windows-gnu"));
        auto *target = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context), false),
            llvm::Function::ExternalLinkage, "target", module);
        auto *return_type = return_width ? llvm::Type::getIntNTy(context, return_width) : llvm::Type::getVoidTy(context);
        owner = llvm::Function::Create(llvm::FunctionType::get(return_type,
            {llvm::Type::getInt1Ty(context)}, false), llvm::Function::ExternalLinkage, "flow", module);
        auto *personality = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getInt32Ty(context), true),
            llvm::Function::ExternalLinkage, "__gxx_personality_seh0", module);
        owner->setPersonalityFn(personality);
        const auto block = [&](const char *name) { return llvm::BasicBlock::Create(context, name, owner); };
        entry = block("entry"); start = block("start"); a = block("a"); b = block("b");
        gate_a = block("normal.a"); gate_b = block("normal.b"); returned = block("returned");
        pad = block("pad"); cleanup = block("cleanup"); dispatch = block("dispatch");
        llvm::IRBuilder<> builder(entry);
        state = builder.CreateAlloca(builder.getInt32Ty());
        correction = builder.CreateAlloca(builder.getInt32Ty());
        auto *exception_type = llvm::StructType::get(context, {builder.getPtrTy(), builder.getInt32Ty()});
        auto *saved = builder.CreateAlloca(exception_type);
        builder.CreateBr(start);
        llvm::Value *condition = owner->getArg(0);
        if (fixed_condition) condition = builder.getInt1(*fixed_condition);
        builder.SetInsertPoint(start); builder.CreateCondBr(condition, a, b);
        builder.SetInsertPoint(a); auto *invoke_a = builder.CreateInvoke(target, gate_a, pad, {});
        builder.SetInsertPoint(b); auto *invoke_b = builder.CreateInvoke(target, gate_b, pad, {});
        builder.SetInsertPoint(gate_a); builder.CreateBr(returned);
        builder.SetInsertPoint(gate_b); builder.CreateBr(returned);
        builder.SetInsertPoint(returned);
        if (return_width) builder.CreateRet(llvm::ConstantInt::get(context, llvm::APInt::getAllOnes(return_width)));
        else builder.CreateRetVoid();
        builder.SetInsertPoint(pad);
        auto *exception = builder.CreateLandingPad(exception_type, 0);
        exception->setCleanup(true);
        builder.CreateStore(exception, saved); builder.CreateBr(cleanup);
        builder.SetInsertPoint(cleanup); builder.CreateResume(builder.CreateLoad(exception_type, saved));
        plan.personality = personality;
        plan.unwind_correction = correction;
        plan.invokes = {{invoke_a, returned, pad, gate_a}, {invoke_b, returned, pad, gate_b}};
        plan.pads = {{exception, pad, cleanup, true, {}}};
        plan.boundaries = {gate_a, gate_b, pad};
        std::vector<llvm::BasicBlock *> bodies{start, a, b, returned, cleanup};
        layout = build_state_layout(*owner, bodies, seed);
        seal = std::make_unique<HybridFlowSeal>(*owner, plan, layout, state, dispatch);
        if (const auto reason = bind_hybrid_eh(plan, *owner, layout, state, dispatch); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(reason));
        auto *old = start->getTerminator();
        builder.SetInsertPoint(old);
        auto *current = builder.CreateLoad(builder.getInt32Ty(), state);
        auto *choice = builder.CreateSelect(condition,
            builder.getInt32(encode_delta(layout.states[start], layout.states[a], layout.transition_salt)),
            builder.getInt32(encode_delta(layout.states[start], layout.states[b], layout.transition_salt)));
        builder.CreateStore(builder.CreateAdd(current, decode_delta(builder, current, choice, layout.transition_salt)), state);
        builder.CreateBr(dispatch); old->eraseFromParent();
        old = entry->getTerminator(); builder.SetInsertPoint(old);
        initial = builder.CreateStore(builder.getInt32(layout.states[start]), state);
        builder.CreateBr(dispatch); old->eraseFromParent();
        builder.SetInsertPoint(dispatch);
        current = builder.CreateLoad(builder.getInt32Ty(), state);
        builder.CreateBr(build_dispatch_tree(*owner, current, layout.sorted_leaves, layout.random_state));
    }

    StateUpdate update(llvm::BasicBlock *body) {
        const auto result = match_state_update(*body, state, layout.transition_salt, dispatch);
        if (!result) llvm::report_fatal_error("fixture lost its production state update");
        return *result;
    }
};

}  // namespace pyobfuscator::native::cff::test
