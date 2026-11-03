#pragma once

#include "scalar_mask.hpp"

namespace llvm { class AllocaInst; class BasicBlock; class BinaryOperator; }

namespace pyobfuscator::native::cff {

const llvm::BinaryOperator *scalar_operation(const llvm::Value *, unsigned, const llvm::BasicBlock *);
bool scalar_constant(const llvm::Value *, std::uint32_t);
const llvm::AllocaInst *match_scalar_mask(const llvm::Value *, const llvm::BasicBlock &, std::uint32_t,
    std::uint32_t, ScalarMaskDomain, const char *state_tag, const char *slot_tag);

}  // namespace pyobfuscator::native::cff
