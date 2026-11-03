#pragma once

#include "recipe.hpp"

namespace pyobfuscator::native::cff {

std::map<std::string, GeneratedDefinition> prepare_module_components(
    llvm::Module &, std::map<std::string, ResolvedRecipe> &, unsigned seed);

}  // namespace pyobfuscator::native::cff
