#pragma once

#include "cff.hpp"
#include "recipe.hpp"
#include "region.hpp"
#include "region_scope.hpp"
#include "region_boundary.hpp"
#include "contribution_edges.hpp"
#include "contribution_edge_flow.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"
#include "transition_proof.hpp"

#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff::test {
struct RegionFixture {
    llvm::LLVMContext context;
    llvm::Module module{"region-boundary", context};
    llvm::Function *owner;
    llvm::BasicBlock *pre = nullptr, *prefix_a = nullptr, *prefix_b = nullptr;
    llvm::BasicBlock *start, *left, *right, *outside_exit, *setup, *exit_leaf, *dispatch;
    llvm::AllocaInst *lease_slot = nullptr, *state;
    llvm::StoreInst *initial;
    llvm::CallInst *outside_call = nullptr;
    llvm::LoadInst *outside_read;
    std::shared_ptr<RegionScope> scope;
    std::unique_ptr<RegionBoundarySeal> boundary;
    std::unique_ptr<ContributionEdgeFlowSeal> flow;
    StateLayout layout;

    explicit RegionFixture(unsigned seed = 17, bool at_entry = false) {
        llvm::IRBuilder<> b(context);
        owner = llvm::Function::Create(llvm::FunctionType::get(b.getInt32Ty(), {b.getPtrTy(), b.getInt32Ty(), b.getInt1Ty()}, false),
            llvm::Function::ExternalLinkage, "region_flow", module);
        auto *slot = new llvm::GlobalVariable(module, b.getInt32Ty(), false, llvm::GlobalValue::InternalLinkage, b.getInt32(0), "result");
        const auto block = [&](const char *name) { return llvm::BasicBlock::Create(context, name, owner); };
        if (!at_entry) { pre = block("pre"); prefix_a = block("prefix.a"); prefix_b = block("prefix.b"); }
        start = block("start"); left = block("left"); right = block("right"); outside_exit = block("out");
        if (!at_entry) {
            b.SetInsertPoint(pre); lease_slot = b.CreateAlloca(b.getPtrTy()); b.CreateStore(owner->getArg(0), lease_slot);
            b.CreateCondBr(owner->getArg(2), prefix_a, prefix_b);
            auto observe = module.getOrInsertFunction("observe", llvm::FunctionType::get(b.getVoidTy(), {b.getInt32Ty()}, false));
            b.SetInsertPoint(prefix_a); outside_call = b.CreateCall(observe, {owner->getArg(1)}); b.CreateBr(start);
            b.SetInsertPoint(prefix_b); b.CreateCall(observe, {b.getInt32(9)}); b.CreateBr(start);
        }
        b.SetInsertPoint(start);
        auto marker = module.getOrInsertFunction("pyobf_native_contribution_site_v1", llvm::FunctionType::get(b.getVoidTy(), {b.getPtrTy(), b.getInt32Ty()}, false));
        llvm::Value *lease = owner->getArg(0);
        if (lease_slot != nullptr) lease = b.CreateLoad(b.getPtrTy(), lease_slot);
        b.CreateCall(marker, {lease, b.getInt32(701)})->setDoesNotThrow(); b.CreateCondBr(owner->getArg(2), left, right);
        b.SetInsertPoint(left); b.CreateStore(b.CreateAdd(owner->getArg(1), b.getInt32(7)), slot); b.CreateBr(outside_exit);
        b.SetInsertPoint(right); b.CreateStore(b.CreateSub(owner->getArg(1), b.getInt32(5)), slot); b.CreateBr(outside_exit);
        b.SetInsertPoint(outside_exit); outside_read = b.CreateLoad(b.getInt32Ty(), slot); b.CreateRet(b.CreateMul(outside_read, b.getInt32(2)));
        if (const auto reason = validate_relative_tree_region(*owner, "start", "out"); !reason.empty()) llvm::report_fatal_error(llvm::StringRef(reason));
        scope = std::make_shared<RegionScope>(*owner, "start", "out");
        const auto predecessors = std::distance(llvm::pred_begin(start), llvm::pred_end(start));
        const auto users = lease_slot == nullptr ? 0u : lease_slot->getNumUses();
        boundary = std::make_unique<RegionBoundarySeal>(*owner, *scope);
        if (std::distance(llvm::pred_begin(start), llvm::pred_end(start)) != predecessors ||
                (lease_slot != nullptr && lease_slot->getNumUses() != users)) llvm::report_fatal_error("region snapshot polluted actual CFG/spill users");
        ResolvedRecipe recipe; recipe.region_scope = scope;
        std::string failure;
        std::vector<ContributionEdgeAnchor> anchors;
        bool multiple = false;
        if (canonical_contribution_source(*owner, recipe, anchors, multiple, failure) != owner->getArg(0) ||
                multiple || anchors.size() != 1 || anchors.front().site != 701 || !failure.empty())
            llvm::report_fatal_error("region snapshot changed canonical lease acquisition");
        setup = llvm::BasicBlock::Create(context, "setup", owner, start);
        for (auto *body : {prefix_a, prefix_b}) if (body != nullptr)
            llvm::cast<llvm::BranchInst>(body->getTerminator())->setSuccessor(0, setup);
        b.SetInsertPoint(setup); b.CreateBr(start);
        b.SetInsertPoint(&*owner->getEntryBlock().getFirstInsertionPt()); state = b.CreateAlloca(b.getInt32Ty()); state->setAlignment(llvm::Align(4));
        exit_leaf = block("exit.leaf"); b.SetInsertPoint(exit_leaf); b.CreateBr(outside_exit);
        for (auto *body : {left, right}) llvm::cast<llvm::BranchInst>(body->getTerminator())->setSuccessor(0, exit_leaf);
        auto bodies = scope->bodies(*owner); bodies.push_back(exit_leaf);
        layout = build_state_layout(*owner, bodies, seed); dispatch = block("dispatch");
        flow = std::make_unique<ContributionEdgeFlowSeal>(*owner, layout, state, dispatch, FlowBoundary{setup, exit_leaf, outside_exit});
        for (auto *body : bodies) {
            if (body == exit_leaf) continue;
            auto *old = llvm::cast<llvm::BranchInst>(body->getTerminator()); b.SetInsertPoint(old);
            auto *current = b.CreateLoad(b.getInt32Ty(), state);
            const auto encoded = [&](unsigned index) { return b.getInt32(encode_delta(layout.states[body], layout.states[old->getSuccessor(index)], layout.transition_salt)); };
            llvm::Value *value = old->isConditional() ? b.CreateSelect(old->getCondition(), encoded(0), encoded(1)) : encoded(0);
            b.CreateStore(b.CreateAdd(current, decode_delta(b, current, value, layout.transition_salt)), state); b.CreateBr(dispatch); old->eraseFromParent();
        }
        auto *old = setup->getTerminator(); b.SetInsertPoint(old);
        initial = b.CreateStore(b.getInt32(layout.states[start]), state); b.CreateBr(dispatch); old->eraseFromParent();
        b.SetInsertPoint(dispatch); auto *current = b.CreateLoad(b.getInt32Ty(), state);
        b.CreateBr(build_dispatch_tree(*owner, current, layout.sorted_leaves, layout.random_state));
    }
    StateUpdate update(llvm::BasicBlock *body) {
        const auto value = match_state_update(*body, state, layout.transition_salt, dispatch);
        if (!value) llvm::report_fatal_error("region fixture lost actual state update");
        return *value;
    }
};
}
