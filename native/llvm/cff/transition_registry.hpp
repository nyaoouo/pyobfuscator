#pragma once

#include "llvm/IR/IRBuilder.h"

namespace pyobfuscator::native::cff {
struct ResolvedRecipe;
struct TransitionModelRegistration {
    const char *name;
    llvm::Value *(*emit)(llvm::IRBuilder<> &, llvm::Value *, llvm::Value *, std::uint32_t, std::uint32_t, const ResolvedRecipe &);
};
llvm::ArrayRef<TransitionModelRegistration> registered_transition_models();
const TransitionModelRegistration *find_transition_model(llvm::StringRef name);
}
