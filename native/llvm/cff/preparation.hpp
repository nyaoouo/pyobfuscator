#pragma once

#include <string>
#include "llvm/ADT/ArrayRef.h"

namespace llvm {
class Function;
class Value;
class BasicBlock;
}

namespace pyobfuscator::native::cff {

struct ResolvedRecipe;
class SiteCoverage;
std::string prepare_components(llvm::Function &function, llvm::Value *state_slot,
                                 const ResolvedRecipe &recipe, SiteCoverage &coverage,
                                 llvm::ArrayRef<const llvm::BasicBlock *> excluded = {});

}  // namespace pyobfuscator::native::cff
