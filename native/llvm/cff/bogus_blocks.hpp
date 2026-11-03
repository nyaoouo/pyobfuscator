#pragma once

#include "recipe.hpp"

namespace pyobfuscator::native::cff {

struct BogusPlacement {
    llvm::Instruction *guard;
    llvm::BasicBlock *body;
};

unsigned bogus_quota(const ResolvedRecipe &recipe, llvm::StringRef component);
std::vector<llvm::Instruction *> select_bogus_sites(SiteCoverage &, llvm::StringRef component, unsigned limit);
BogusPlacement create_bogus_block(llvm::Instruction &anchor, llvm::StringRef component,
    SiteCoverage &coverage, llvm::Value *state, std::uint32_t seed);
unsigned bind_bogus_block(llvm::BasicBlock &body, llvm::Value *state_slot,
                           std::uint32_t salt, SiteCoverage *coverage,
                           llvm::StringRef component);
void mark_bogus_result(llvm::Value *value, llvm::Value *state, SiteCoverage &);

}  // namespace pyobfuscator::native::cff
