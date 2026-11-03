#pragma once

#include <cstdint>

#include "llvm/IR/IRBuilder.h"

namespace pyobfuscator::native::cff {

std::uint32_t encode_delta(std::uint32_t source, std::uint32_t target,
                           std::uint32_t salt) noexcept;
llvm::Value *decode_delta(llvm::IRBuilder<> &builder, llvm::Value *current,
                          llvm::Value *encoded, std::uint32_t salt);

}  // namespace pyobfuscator::native::cff
