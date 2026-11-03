#include "dispatch_proof.hpp"
#include "transition_proof.hpp"

#include <vector>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::string verify_dispatch_graph(const llvm::Function &function, const llvm::AllocaInst *slot,
    const llvm::BasicBlock *dispatch, const std::map<const llvm::BasicBlock *, std::uint32_t> &states,
    const std::set<const llvm::BasicBlock *> &original, std::set<const llvm::BasicBlock *> &tree) {
    tree.clear();
    if (states.empty()) return "hybrid flow dispatcher has no planned bodies";
    if (dispatch->size() != 2) return "hybrid flow dispatcher has no unique state read";
    const auto *branch = llvm::dyn_cast<llvm::BranchInst>(dispatch->getTerminator());
    const auto *read = llvm::dyn_cast<llvm::LoadInst>(&dispatch->front());
    if (branch == nullptr || !branch->isUnconditional() ||
        !simple_state_read(read, slot, dispatch)) return "hybrid flow dispatcher has no unique state read";
    std::set<const llvm::BasicBlock *> leaves;
    std::set<std::uint32_t> state_values;
    for (const auto &[body, value] : states) state_values.insert(value);
    struct Range { const llvm::BasicBlock *node; std::uint64_t lower, upper; };
    std::vector<Range> pending{{branch->getSuccessor(0), 0, 1ull << 32}};
    bool valid = true;
    while (!pending.empty() && valid) {
        const auto [node, lower, upper] = pending.back();
        pending.pop_back();
        if (node->getParent() != &function || original.count(node) || !tree.insert(node).second ||
            tree.size() > states.size() * 2 - 1) { valid = false; break; }
        const auto *edge = llvm::dyn_cast<llvm::BranchInst>(node->getTerminator());
        if (edge == nullptr) { valid = false; break; }
        if (edge->isUnconditional()) {
            const auto found = states.find(edge->getSuccessor(0));
            valid = node->size() == 1 && found != states.end() && leaves.insert(found->first).second &&
                lower <= found->second && found->second < upper;
            continue;
        }
        const auto *compare = llvm::dyn_cast<llvm::ICmpInst>(edge->getCondition());
        const auto *pivot = compare == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(compare->getOperand(1));
        if (node->size() != 2 || compare == nullptr || compare->getParent() != node ||
            compare->getPredicate() != llvm::CmpInst::ICMP_UGE || compare->hasPoisonGeneratingAnnotations() ||
            compare->getOperand(0) != read || pivot == nullptr || !pivot->getType()->isIntegerTy(32)) { valid = false; break; }
        const auto boundary = pivot->getZExtValue();
        if (!(lower < boundary && boundary < upper) || state_values.count(boundary)) { valid = false; break; }
        pending.push_back({edge->getSuccessor(0), boundary, upper});
        pending.push_back({edge->getSuccessor(1), lower, boundary});
    }
    if (!valid || leaves.size() != states.size() ||
        tree.size() != states.size() * 2 - 1) return "hybrid flow comparison tree changed its planned state partition";
    return {};
}

}  // namespace pyobfuscator::native::cff
