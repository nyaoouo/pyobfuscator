#pragma once

namespace llvm { class BranchInst; class Value; class BasicBlock; }
namespace pyobfuscator::native::cff {
struct StateLayout;
struct ResolvedRecipe;
class SiteCoverage;
void rewrite_normal_transition(llvm::BranchInst &, llvm::Value *state, const StateLayout &,
    const ResolvedRecipe &, SiteCoverage &, llvm::BasicBlock *dispatch);
}
