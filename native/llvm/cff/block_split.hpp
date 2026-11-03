#pragma once

#include "recipe.hpp"

namespace pyobfuscator::native::cff {
struct RequestedSite;

std::vector<InstructionSite> discover_requested_splits(llvm::Function &, const ResolvedRecipe &,
    llvm::ArrayRef<RequestedSite>);

}  // namespace pyobfuscator::native::cff
