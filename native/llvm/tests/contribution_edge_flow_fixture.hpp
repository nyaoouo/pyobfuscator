#pragma once

#include "contribution_edge_flow.hpp"
#include "cff.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"
#include "transition_proof.hpp"

#include <memory>
#include <optional>

#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff::test {
struct EdgeFlowFixture {
    llvm::LLVMContext context;
    llvm::Module module{"contribution-edge-flow", context};
    llvm::Function *owner;
    llvm::BasicBlock *entry, *start, *gateway, *left, *right, *returned, *dispatch;
    llvm::AllocaInst *state;
    llvm::StoreInst *initial;
    StateLayout layout;
    std::unique_ptr<ContributionEdgeFlowSeal> seal;

    explicit EdgeFlowFixture(unsigned seed = 17, std::optional<bool> fixed = std::nullopt, bool parallel = false) {
        owner = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context),
            {llvm::Type::getInt1Ty(context)}, false), llvm::Function::ExternalLinkage, "edge_flow", module);
        const auto block = [&](const char *name) { return llvm::BasicBlock::Create(context, name, owner); };
        entry = block("entry"); start = block("start"); gateway = block("gateway");
        left = block("left"); right = block("right"); returned = block("returned"); dispatch = block("dispatch");
        llvm::IRBuilder<> builder(entry);
        state = builder.CreateAlloca(builder.getInt32Ty()); state->setAlignment(llvm::Align(4));
        builder.CreateBr(start);
        llvm::Value *condition = owner->getArg(0);
        if (fixed) condition = builder.getInt1(*fixed);
        builder.SetInsertPoint(start); builder.CreateCondBr(condition, gateway, parallel ? gateway : right);
        builder.SetInsertPoint(gateway); builder.CreateBr(left);
        builder.SetInsertPoint(left);
        if (parallel) builder.CreateCondBr(condition, right, returned); else builder.CreateBr(returned);
        builder.SetInsertPoint(right); builder.CreateBr(returned);
        builder.SetInsertPoint(returned); builder.CreateRetVoid();
        std::vector<llvm::BasicBlock *> bodies{start, gateway, left, right, returned};
        layout = build_state_layout(*owner, bodies, seed);
        seal = std::make_unique<ContributionEdgeFlowSeal>(*owner, layout, state, dispatch);
        for (auto *body : bodies) {
            auto *branch = llvm::dyn_cast<llvm::BranchInst>(body->getTerminator());
            if (branch == nullptr) continue;
            builder.SetInsertPoint(branch);
            auto *current = builder.CreateLoad(builder.getInt32Ty(), state);
            const auto value = [&](unsigned index) { return builder.getInt32(encode_delta(layout.states[body],
                layout.states[branch->getSuccessor(index)], layout.transition_salt)); };
            auto *encoded = branch->isConditional() ? builder.CreateSelect(branch->getCondition(), value(0), value(1)) : value(0);
            builder.CreateStore(builder.CreateAdd(current, decode_delta(builder, current, encoded, layout.transition_salt)), state);
            builder.CreateBr(dispatch); branch->eraseFromParent();
        }
        auto *old = entry->getTerminator(); builder.SetInsertPoint(old);
        initial = builder.CreateStore(builder.getInt32(layout.states[start]), state);
        builder.CreateBr(dispatch); old->eraseFromParent();
        builder.SetInsertPoint(dispatch);
        auto *current = builder.CreateLoad(builder.getInt32Ty(), state);
        builder.CreateBr(build_dispatch_tree(*owner, current, layout.sorted_leaves, layout.random_state));
    }

    StateUpdate update(llvm::BasicBlock *body) {
        const auto result = match_state_update(*body, state, layout.transition_salt, dispatch);
        if (!result) llvm::report_fatal_error("edge fixture lost its actual state update");
        return *result;
    }
};
}
