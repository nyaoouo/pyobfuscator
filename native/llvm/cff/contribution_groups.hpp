#pragma once

#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/JSON.h"

#include <string>
#include <vector>

namespace pyobfuscator::native::cff {
struct ResolvedRecipe;
class TransitionLayers;
class BogusControls;
class SiteCoverage;
unsigned prepare_contribution_group_sites(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
llvm::Value *bind_contribution_group_transition(llvm::IRBuilder<> &, llvm::Value *, std::uint32_t state,
    std::uint32_t seed, const ResolvedRecipe &);
std::vector<const llvm::CallInst *> contribution_group_queries(const llvm::BasicBlock &);
std::string validate_contribution_group_gates(const llvm::Function &, const TransitionLayers *, const BogusControls * = nullptr);
const llvm::Value *contribution_mask_observation(const llvm::Value *, std::uint32_t salt, const llvm::BasicBlock *);
void report_contribution_groups(llvm::json::Object &, const llvm::Function &, const ResolvedRecipe &);
}
