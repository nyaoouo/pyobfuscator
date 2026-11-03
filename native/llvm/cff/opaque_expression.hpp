#pragma once

#include <cstdint>

#include "llvm/IR/IRBuilder.h"

namespace pyobfuscator::native::cff {

llvm::Value *emit_opaque_true(llvm::IRBuilder<> &builder, llvm::Value *state_slot,
                               std::uint32_t salt, unsigned family);

}  // namespace pyobfuscator::native::cff
