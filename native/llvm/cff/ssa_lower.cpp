#include "cff.hpp"
#include "site_report.hpp"

#include <set>

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/Local.h"

namespace pyobfuscator::native::cff {

void lower_cross_block_ssa(llvm::Function &function, SiteCoverage *coverage) {
    std::set<llvm::BasicBlock *> previous;
    if (coverage != nullptr) for (auto &block : function) previous.insert(&block);
    auto &entry = function.getEntryBlock();
    llvm::SmallVector<llvm::PHINode *, 8> phis;
    for (auto &block : function) {
        for (auto &phi : block.phis()) {
            phis.push_back(&phi);
        }
    }
    for (auto *phi : phis) {
        llvm::DemotePHIToStack(phi, entry.getFirstInsertionPt());
    }

    llvm::SmallVector<llvm::Instruction *, 16> cross_block;
    for (auto &block : function) {
        for (auto &instruction : block) {
            if (llvm::isa<llvm::AllocaInst>(instruction) && &block == &entry) {
                continue;
            }
            for (const auto *user : instruction.users()) {
                const auto *use = llvm::dyn_cast<llvm::Instruction>(user);
                if (use != nullptr && use->getParent() != &block) {
                    cross_block.push_back(&instruction);
                    break;
                }
            }
        }
    }
    for (auto *instruction : cross_block) {
        llvm::DemoteRegToStack(*instruction, false, entry.getFirstInsertionPt());
    }
    if (coverage != nullptr) for (auto &block : function)
        if (!previous.count(&block)) coverage->origins().set(block, BlockRole::routing);
}

}  // namespace pyobfuscator::native::cff
