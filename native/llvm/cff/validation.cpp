#include "cff.hpp"
#include "control_validation.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
namespace pyobfuscator::native::cff {

std::string validate_cfg_shape(const llvm::Function &function, bool landingpad_eh) {
    if (function.hasFnAttribute("pyobf.cff.transformed"))
        return "relative-tree refuses an already state-bound function";
    if (function.isDeclaration()) {
        return "selected function is a declaration";
    }
    if (const auto reason = validate_control_semantics(function); !reason.empty()) return reason;
    const auto *entry = &function.getEntryBlock();
    llvm::SmallPtrSet<const llvm::BasicBlock *, 32> reachable;
    llvm::SmallVector<const llvm::BasicBlock *, 16> pending{entry};
    while (!pending.empty()) {
        const auto *block = pending.pop_back_val();
        if (!reachable.insert(block).second) {
            continue;
        }
        for (const auto *successor : llvm::successors(block)) {
            pending.push_back(successor);
        }
    }
    if (reachable.size() != function.size()) {
        return "relative-tree does not cover unreachable body blocks";
    }
    for (const auto &block : function) {
        for (const auto &instruction : block) {
            if (llvm::isa<llvm::PHINode>(instruction) && &block == entry) {
                return "relative-tree does not support entry PHI nodes";
            }
            if (llvm::isa<llvm::PHINode>(instruction) &&
                (instruction.getType()->isTokenTy() || !instruction.getType()->isSized())) {
                return "relative-tree cannot lower an unsized PHI value";
            }
            for (const auto *user : instruction.users()) {
                const auto *use = llvm::dyn_cast<llvm::Instruction>(user);
                if (use != nullptr && use->getParent() != &block &&
                    !(&block == entry && llvm::isa<llvm::AllocaInst>(instruction))) {
                    if (instruction.getType()->isTokenTy() ||
                        !instruction.getType()->isSized()) {
                        return "relative-tree cannot lower an unsized cross-block SSA value";
                    }
                }
            }
        }
        const auto *term = block.getTerminator();
        if (!llvm::isa<llvm::BranchInst>(term) && !llvm::isa<llvm::SwitchInst>(term) &&
            !llvm::isa<llvm::ReturnInst>(term) && !llvm::isa<llvm::UnreachableInst>(term) &&
            !(landingpad_eh && (llvm::isa<llvm::InvokeInst>(term) || llvm::isa<llvm::ResumeInst>(term)))) {
            return "relative-tree supports branches, switches, and returns only";
        }
        for (unsigned index = 0; index < term->getNumSuccessors(); ++index) {
            if (term->getSuccessor(index) == entry) {
                return "relative-tree does not support branches to the entry block";
            }
        }
    }
    return {};
}

std::string validate_relative_tree(const llvm::Function &function) {
    return validate_cfg_shape(function, false);
}

}  // namespace pyobfuscator::native::cff
