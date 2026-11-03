#pragma once

#include "recipe.hpp"
#include "llvm/Support/JSON.h"

namespace llvm { class Module; }

namespace pyobfuscator::native::cff {
llvm::json::Object generated_ownership(const llvm::Module &,
    const std::map<std::string, GeneratedDefinition> &, const llvm::json::Array &);
void write_untransformed_inventory(const llvm::Module &, llvm::StringRef path);
}
