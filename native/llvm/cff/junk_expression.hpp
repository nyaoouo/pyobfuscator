#pragma once

#include <cstdint>

#include "llvm/IR/IRBuilder.h"

namespace pyobfuscator::native::cff {

std::uint32_t junk_mix_value(std::uint32_t value, std::uint32_t salt, unsigned rounds);
llvm::Value *emit_junk_mix(llvm::IRBuilder<> &builder, llvm::Value *value,
                             std::uint32_t salt, unsigned rounds);

}  // namespace pyobfuscator::native::cff
