#pragma once

#include "recipe.hpp"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_external_calls(llvm::Function &, const ResolvedRecipe &);
void plan_external_calls(llvm::Module &, const std::map<std::string, ResolvedRecipe> &,
                           std::vector<GeneratedDefinition> &);
unsigned normalize_external_calls(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);

}  // namespace pyobfuscator::native::cff
