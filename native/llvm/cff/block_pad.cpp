#include "cff.hpp"
#include "site_report.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

void pad_small_cfg(llvm::Function &function, unsigned min_blocks, SiteCoverage *coverage) {
    // The dispatcher needs three bodies. Add entry transitions before SSA lowering so
    // allocas in the former entry are treated as cross-block values when necessary.
    while (function.size() < min_blocks) {
        auto *old_entry = &function.getEntryBlock();
        auto *new_entry = llvm::BasicBlock::Create(function.getContext(), "pyobf.entry.pad",
                                                   &function, old_entry);
        llvm::BranchInst::Create(old_entry, new_entry);
        if (coverage != nullptr) coverage->origins().set(*new_entry, BlockRole::shape);
    }
}

}  // namespace pyobfuscator::native::cff
