#pragma once

#include "bogus_controls.hpp"
#include "contribution_edge_flow.hpp"
#include "opaque_expression.hpp"
#include "scalar_mask.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"

#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff::test {
struct BogusControlFixture {
    llvm::LLVMContext context;
    llvm::Module module{"bogus-control", context};
    llvm::Function *owner;
    llvm::BasicBlock *entry, *guard, *normal, *decoy, *dispatch;
    llvm::AllocaInst *state;
    llvm::Instruction *predicate, *result;
    llvm::StoreInst *work;
    StateLayout layout;
    std::unique_ptr<BogusControls> controls;
    std::unique_ptr<ContributionEdgeFlowSeal> flow;
    explicit BogusControlFixture(unsigned seed = 17, bool hidden = false) {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        llvm::IRBuilder<> b(context);
        owner = llvm::Function::Create(llvm::FunctionType::get(b.getInt32Ty(), {b.getInt32Ty()}, false),
            llvm::Function::ExternalLinkage, "bogus_owner", module);
        const auto block = [&](const char *name) { return llvm::BasicBlock::Create(context, name, owner); };
        entry = block("entry"); guard = block("guard"); normal = block("normal"); decoy = block("decoy");
        b.SetInsertPoint(entry); state = b.CreateAlloca(b.getInt32Ty()); state->setAlignment(llvm::Align(4)); b.CreateBr(guard);
        b.SetInsertPoint(guard); predicate = llvm::cast<llvm::Instruction>(emit_opaque_true(b, state, seed, seed % 3));
        auto *source = b.CreateCondBr(predicate, normal, decoy);
        b.SetInsertPoint(decoy); result = llvm::cast<llvm::Instruction>(b.CreateAdd(b.CreateLoad(b.getInt32Ty(), state), b.getInt32(7)));
        result->setMetadata("pyobf.cff.bogus-result", llvm::MDNode::get(context, {}));
        work = b.CreateStore(result, state); b.CreateBr(normal);
        b.SetInsertPoint(normal); b.CreateRet(b.getInt32(7));
        std::vector<llvm::BasicBlock *> bodies{guard, normal, decoy};
        layout = build_state_layout(*owner, bodies, seed);
        BogusControlPlan plan{{source, normal, decoy, predicate, result, work, "bogus-clones", "source:guard", seed}};
        controls = std::make_unique<BogusControls>(*owner, layout, state, plan,
            hidden ? std::optional<std::uint32_t>(0x12345678u) : std::nullopt);
        dispatch = block("dispatch");
        flow = std::make_unique<ContributionEdgeFlowSeal>(*owner, layout, state, dispatch);
        if (hidden) for (auto iterator = guard->begin(); iterator != guard->end();) {
            auto &instruction = *iterator++;
            if (!llvm::isa<llvm::BinaryOperator, llvm::ICmpInst>(instruction)) continue;
            for (unsigned index = 0; index != instruction.getNumOperands(); ++index)
                if (const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(index))) {
                    llvm::IRBuilder<> decode(&instruction);
                    instruction.setOperand(index, emit_scalar_literal(decode, *constant, state, layout.states[guard], 0x12345678u));
                }
        }
        b.SetInsertPoint(entry->getTerminator()); b.CreateStore(b.getInt32(layout.states[guard]), state);
        entry->getTerminator()->eraseFromParent(); b.SetInsertPoint(entry); b.CreateBr(dispatch);
        for (auto *body : {guard, decoy}) {
            auto *branch = llvm::cast<llvm::BranchInst>(body->getTerminator()); b.SetInsertPoint(branch);
            llvm::Value *encoded = b.getInt32(encode_delta(layout.states[body], layout.states[branch->getSuccessor(0)], layout.transition_salt));
            if (branch->isConditional()) encoded = b.CreateSelect(branch->getCondition(), encoded,
                b.getInt32(encode_delta(layout.states[body], layout.states[branch->getSuccessor(1)], layout.transition_salt)));
            auto *current = b.CreateLoad(b.getInt32Ty(), state);
            b.CreateStore(b.CreateAdd(current, decode_delta(b, current, encoded, layout.transition_salt)), state);
            b.CreateBr(dispatch); branch->eraseFromParent();
        }
        b.SetInsertPoint(dispatch); auto *current = b.CreateLoad(b.getInt32Ty(), state);
        b.CreateBr(build_dispatch_tree(*owner, current, layout.sorted_leaves, layout.random_state));
    }
    std::string verify() const { return flow->verify(*owner, controls.get()); }
    bool retained() const { return BogusControls(*owner).verify(*owner).empty(); }
    llvm::SelectInst *choice() {
        for (auto &instruction : *guard) if (auto *choice = llvm::dyn_cast<llvm::SelectInst>(&instruction)) return choice;
        llvm::report_fatal_error("bogus fixture has no actual choice");
    }
};
}
