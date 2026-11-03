#include "hybrid_flow.hpp"
#include "state_layout.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

HybridFlowSeal::HybridFlowSeal(const llvm::Function &function, const HybridEhPlan &plan,
    const StateLayout &layout, const llvm::AllocaInst *state, const llvm::BasicBlock *dispatch)
    : owner_(&function), state_(state), correction_(plan.unwind_correction), dispatch_(dispatch), salt_(layout.transition_salt) {
    for (const auto &[body, value] : layout.states) states_.emplace(body, value);
    for (const auto &block : function) original_.insert(&block);
    const auto *entry = llvm::dyn_cast<llvm::BranchInst>(function.getEntryBlock().getTerminator());
    if (entry == nullptr || !entry->isUnconditional() || !states_.count(entry->getSuccessor(0)))
        error_ = "hybrid flow has no planned original entry";
    else initial_ = states_.at(entry->getSuccessor(0));
    std::set<std::uint32_t> unique;
    for (const auto &[body, value] : states_) {
        if (!unique.insert(value).second) error_ = "hybrid flow planned states are not unique";
        const auto *term = body->getTerminator();
        if (const auto *branch = llvm::dyn_cast<llvm::BranchInst>(term)) {
            const auto *yes = branch->getSuccessor(0);
            const auto *no = branch->isConditional() ? branch->getSuccessor(1) : nullptr;
            if (!states_.count(yes) || (no != nullptr && !states_.count(no)))
                error_ = "hybrid flow normal source escapes its planned bodies";
            const auto *condition = branch->isConditional() ? branch->getCondition() : nullptr;
            normal_.push_back({body, yes, no, condition, llvm::dyn_cast_or_null<llvm::Constant>(condition)});
        } else {
            Terminal terminal{term, {}};
            for (const auto &operand : term->operands()) terminal.operands.push_back(operand.get());
            terminals_.emplace(body, std::move(terminal));
        }
    }
    for (const auto &pad : plan.pads) pads_.push_back({pad.header, pad.continuation});
    for (const auto &edge : plan.invokes) {
        const llvm::BasicBlock *continuation = nullptr;
        for (const auto &pad : pads_) if (pad.header == edge.unwind) continuation = pad.continuation;
        if (!states_.count(edge.instruction->getParent()) || !states_.count(edge.normal) ||
            continuation == nullptr || !states_.count(continuation)) error_ = "hybrid flow invoke has no planned continuation";
        invokes_.push_back({edge.instruction, edge.instruction->getParent(), edge.normal, edge.unwind, edge.gateway, continuation});
    }
}

}  // namespace pyobfuscator::native::cff
