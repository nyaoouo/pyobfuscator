#include "call_preparation.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

bool preparation_state_routes_to(const llvm::BasicBlock &body, const llvm::AllocaInst *slot, std::uint32_t expected) {
    const auto *entry = llvm::dyn_cast<llvm::BranchInst>(body.getParent()->getEntryBlock().getTerminator());
    if (entry == nullptr || !entry->isUnconditional() || slot == nullptr) return false;
    const auto *count = llvm::dyn_cast<llvm::ConstantInt>(slot->getArraySize());
    if (count == nullptr || !count->isOne() || slot->getParent() != &body.getParent()->getEntryBlock()) return false;
    for (const auto *user : slot->users()) {
        if (const auto *read = llvm::dyn_cast<llvm::LoadInst>(user)) {
            if (read->isAtomic() || read->getPointerOperand() != slot || !read->getType()->isIntegerTy(32)) return false;
        } else if (const auto *write = llvm::dyn_cast<llvm::StoreInst>(user)) {
            if (!write->isSimple() || write->getPointerOperand() != slot || !write->getValueOperand()->getType()->isIntegerTy(32)) return false;
        } else return false;
    }
    const auto *dispatch = entry->getSuccessor(0);
    const auto *branch = llvm::dyn_cast<llvm::BranchInst>(dispatch->getTerminator());
    if (branch == nullptr || !branch->isUnconditional() || dispatch->size() != 2) return false;
    const auto *state = llvm::dyn_cast<llvm::LoadInst>(&dispatch->front());
    if (state == nullptr || !state->isSimple() || state->getPointerOperand() != slot || !state->getType()->isIntegerTy(32)) return false;
    const auto *node = branch->getSuccessor(0);
    std::set<const llvm::BasicBlock *> visited;
    while (visited.insert(node).second && visited.size() <= body.getParent()->size()) {
        const auto *edge = llvm::dyn_cast<llvm::BranchInst>(node->getTerminator());
        if (edge == nullptr) return false;
        if (edge->isUnconditional()) return node->size() == 1 && edge->getSuccessor(0) == &body;
        const auto *compare = llvm::dyn_cast<llvm::ICmpInst>(edge->getCondition());
        const auto *pivot = compare == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(compare->getOperand(1));
        if (node->size() != 2 || compare == nullptr || compare->getParent() != node ||
            compare->getPredicate() != llvm::CmpInst::ICMP_UGE || compare->getOperand(0) != state ||
            pivot == nullptr || !pivot->getType()->isIntegerTy(32)) return false;
        node = edge->getSuccessor(expected >= pivot->getZExtValue() ? 0 : 1);
    }
    return false;
}

}  // namespace pyobfuscator::native::cff
