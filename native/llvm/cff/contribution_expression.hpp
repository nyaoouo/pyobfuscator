#pragma once

#include "llvm/IR/IRBuilder.h"

#include <cstdint>

namespace pyobfuscator::native::cff {

llvm::Value *emit_contribution_delta(llvm::IRBuilder<> &, llvm::Value *current,
    llvm::Value *observed, std::uint32_t sealed, std::uint32_t contribution_salt,
    std::uint32_t transition_salt);

}  // namespace pyobfuscator::native::cff
