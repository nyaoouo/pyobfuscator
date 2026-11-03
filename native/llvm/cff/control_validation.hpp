#pragma once

#include <string>

namespace llvm { class Function; }

namespace pyobfuscator::native::cff {

std::string validate_control_semantics(const llvm::Function &);

}  // namespace pyobfuscator::native::cff
