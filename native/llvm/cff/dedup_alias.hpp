#pragma once

#include "llvm/IR/Instruction.h"
#include "llvm/IR/ValueHandle.h"

namespace llvm { class Instruction; class Function; }
namespace pyobfuscator::native::cff {
struct ResolvedRecipe;
class SiteCoverage;

// Only the semantic normalizer can grant this compiler-owned construction witness.
class DedupAlias {
public:
    llvm::Instruction *source() const { return llvm::dyn_cast_or_null<llvm::Instruction>(source_); }
    llvm::Instruction *target() const { return llvm::dyn_cast_or_null<llvm::Instruction>(target_); }
private:
    DedupAlias(llvm::Instruction &source, llvm::Instruction &target) : source_(&source), target_(&target) {}
    friend unsigned deduplicate_blocks(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
    llvm::WeakVH source_, target_;
};
}
