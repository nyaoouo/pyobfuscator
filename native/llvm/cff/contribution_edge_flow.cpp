#include "contribution_edge_flow.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"
#include "transition_proof.hpp"
#include "scalar_proof.hpp"
#include "dispatch_proof.hpp"
#include "transition_binding.hpp"
#include "state_binding_proof.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
ContributionEdgeFlowSeal::ContributionEdgeFlowSeal(const llvm::Function &function, const StateLayout &layout,
    const llvm::AllocaInst *state, const llvm::BasicBlock *dispatch, FlowBoundary boundary)
    : owner_(&function), state_(state), dispatch_(dispatch), boundary_(boundary), salt_(layout.transition_salt) {
    if (boundary_.setup == nullptr) boundary_.setup = &function.getEntryBlock();
    for (const auto &[body, value] : layout.states) states_.emplace(body, value);
    for (const auto &body : function) original_.insert(&body);
    initial_ = layout.states.lookup(boundary_.setup->getTerminator()->getSuccessor(0));
    for (const auto &body : function) {
        if (!layout.states.contains(&body)) continue;
        if (&body == boundary_.exit_leaf) continue;
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(body.getTerminator());
        if (branch == nullptr) { terminals_.push_back(const_cast<llvm::Instruction *>(body.getTerminator())); continue; }
        const auto state = layout.states.lookup(&body);
        const auto yes = encode_delta(state, layout.states.lookup(branch->getSuccessor(0)), salt_);
        const auto no = branch->isConditional() ? encode_delta(state, layout.states.lookup(branch->getSuccessor(1)), salt_) : yes;
        jumps_.push_back({&body, branch->isConditional() ? const_cast<llvm::Value *>(branch->getCondition()) : nullptr, yes, no, state});
    }
}
std::string ContributionEdgeFlowSeal::verify(const llvm::Function &function, const TransitionBinding *binding) const {
    if (&function != owner_) return "automatic contribution flow owner changed";
    if (binding != nullptr)
        if (const auto reason = binding->verify(function); !reason.empty()) return reason;
    if (!valid_state_storage(state_, &function.getEntryBlock())) return "automatic contribution state storage changed";
    std::set<const llvm::BasicBlock *> blocks;
    for (const auto &body : function) blocks.insert(&body);
    for (const auto *body : original_) if (!blocks.count(body)) return "automatic contribution flow lost a planned body";
    std::set<const llvm::BasicBlock *> tree;
    if (const auto reason = verify_dispatch_graph(function, state_, dispatch_, states_, original_, tree); !reason.empty()) return reason;
    if (blocks.size() != original_.size() + tree.size()) return "automatic contribution flow added unplanned blocks";
    const auto *entry = llvm::dyn_cast<llvm::BranchInst>(boundary_.setup->getTerminator());
    const auto *initial = entry == nullptr ? nullptr : llvm::dyn_cast_or_null<llvm::StoreInst>(entry->getPrevNode());
    if (entry == nullptr || !entry->isUnconditional() || entry->getSuccessor(0) != dispatch_ || initial == nullptr ||
            initial->getPointerOperand() != state_ || !initial->isSimple() || !scalar_constant(initial->getValueOperand(), initial_))
        return "automatic contribution initial state changed";
    if (boundary_.exit_leaf != nullptr) {
        const auto *exit = llvm::dyn_cast<llvm::BranchInst>(boundary_.exit_leaf->getTerminator());
        if (boundary_.setup->size() != 2 + (state_->getParent() == boundary_.setup) ||
                boundary_.exit_leaf->size() != 1 || exit == nullptr || !exit->isUnconditional() ||
                exit->getSuccessor(0) != boundary_.exit) return "region setup or sole exit boundary changed";
    }
    std::set<const llvm::StoreInst *> stores{initial};
    for (const auto &jump : jumps_) {
        const auto update = match_state_update(*jump.body, state_, salt_, dispatch_);
        if (!update) return "automatic original-edge flow lost its actual state update";
        stores.insert(update->store);
        const auto *encoded = binding == nullptr ? update->encoded : binding->normal_encoded(*jump.body, update->encoded);
        if (encoded == nullptr) return "automatic contribution transition layer lost its verified core";
        if (binding != nullptr && jump.condition == nullptr &&
                binding->covers_unconditional(*jump.body, jump.state, jump.yes)) continue;
        if (const auto *condition = llvm::dyn_cast_or_null<llvm::ConstantInt>(jump.condition)) {
            if (!scalar_constant(encoded, condition->isZero() ? jump.no : jump.yes)) return "automatic constant decision route changed";
        } else if (jump.condition == nullptr || (jump.yes == jump.no && scalar_constant(encoded, jump.yes))) {
            if (!scalar_constant(encoded, jump.yes)) return "automatic original-edge route bypasses its selected destination";
        } else {
            const auto *choice = llvm::dyn_cast<llvm::SelectInst>(encoded);
            if (choice == nullptr || choice->getParent() != jump.body || choice->getCondition() != jump.condition ||
                    !scalar_constant(choice->getTrueValue(), jump.yes) || !scalar_constant(choice->getFalseValue(), jump.no))
                return "automatic original decision route changed";
        }
    }
    for (const auto &terminal : terminals_) {
        const auto *instruction = llvm::dyn_cast_or_null<llvm::Instruction>(terminal);
        if (instruction == nullptr || instruction->getParent()->getTerminator() != instruction)
            return "automatic contribution terminal flow changed";
    }
    for (const auto *user : state_->users()) {
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user); store != nullptr && binding != nullptr && binding->owns_state_write(*store)) continue;
        if (const auto *read = llvm::dyn_cast<llvm::LoadInst>(user); read != nullptr && binding != nullptr && binding->owns_state_read(*read)) continue;
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user); store != nullptr && stores.count(store)) continue;
        if (const auto *read = llvm::dyn_cast<llvm::LoadInst>(user); read != nullptr && read->getPointerOperand() == state_ && read->isSimple()) continue;
        return "automatic contribution state storage has an unplanned writer or escape";
    }
    return verify_state_bindings(function, state_, states_);
}
}
