#include "region.hpp"
#include "control_validation.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::string validate_relative_tree_region(const llvm::Function &function,
                                          llvm::StringRef entry_name,
                                          llvm::StringRef exit_name) {
    if (function.hasFnAttribute("pyobf.cff.transformed"))
        return "relative-tree-region refuses an already state-bound function";
    if (function.isDeclaration()) {
        return "selected region function is a declaration";
    }
    if (const auto reason = validate_control_semantics(function); !reason.empty()) return reason;
    const llvm::BasicBlock *entry = nullptr;
    const llvm::BasicBlock *exit = nullptr;
    for (const auto &block : function) {
        if (block.getName() == entry_name) entry = &block;
        if (block.getName() == exit_name) exit = &block;
    }
    if (entry == nullptr || exit == nullptr || entry == exit) {
        return "region needs distinct existing named entry and exit blocks";
    }
    if (exit == &function.getEntryBlock()) {
        return "region exit cannot be the function entry";
    }
    llvm::SmallPtrSet<const llvm::BasicBlock *, 32> reachable;
    llvm::SmallVector<const llvm::BasicBlock *, 16> pending{&function.getEntryBlock()};
    while (!pending.empty()) {
        const auto *block = pending.pop_back_val();
        if (!reachable.insert(block).second) continue;
        for (const auto *next : llvm::successors(block)) pending.push_back(next);
    }
    if (!reachable.contains(entry)) return "region entry is unreachable";

    llvm::SmallPtrSet<const llvm::BasicBlock *, 32> bodies;
    pending.push_back(entry);
    while (!pending.empty()) {
        const auto *block = pending.pop_back_val();
        if (block == exit || !bodies.insert(block).second) continue;
        for (const auto *next : llvm::successors(block)) pending.push_back(next);
    }
    if (bodies.size() < 3) return "region needs at least three body blocks";
    if (llvm::isa<llvm::PHINode>(exit->front())) {
        return "region exit PHI cannot be rewritten safely";
    }
    bool decision = false;
    for (const auto *block : bodies) {
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(block->getTerminator());
        if (branch == nullptr) return "region supports branch terminators only";
        decision |= branch->isConditional();
        for (const auto &instruction : *block) {
            if (llvm::isa<llvm::PHINode>(instruction)) {
                return "region body PHI cannot be rewritten safely";
            }
            for (const auto *user : instruction.users()) {
                const auto *use = llvm::dyn_cast<llvm::Instruction>(user);
                if (use == nullptr || use->getParent() != block) {
                    return "region-defined value has a cross-block use";
                }
            }
        }
        for (const auto *previous : llvm::predecessors(block)) {
            if (block != entry && !bodies.contains(previous)) {
                return "region has an external entry into a body block";
            }
            if (block == entry && !bodies.contains(previous) &&
                !llvm::isa<llvm::BranchInst>(previous->getTerminator()) &&
                !llvm::isa<llvm::SwitchInst>(previous->getTerminator())) {
                return "region entry has an unsupported external predecessor";
            }
        }
    }
    if (!decision) return "region has no conditional decision flow";

    llvm::SmallPtrSet<const llvm::BasicBlock *, 32> reaches_exit;
    pending.push_back(exit);
    while (!pending.empty()) {
        const auto *block = pending.pop_back_val();
        if (!reaches_exit.insert(block).second) continue;
        for (const auto *previous : llvm::predecessors(block)) {
            if (bodies.contains(previous)) pending.push_back(previous);
        }
    }
    for (const auto *block : bodies) {
        if (!reaches_exit.contains(block)) return "region body cannot reach exit";
    }
    return {};
}

}  // namespace pyobfuscator::native::cff
