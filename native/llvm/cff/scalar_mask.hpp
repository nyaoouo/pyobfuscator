#pragma once

#include <cstdint>

#include "llvm/ADT/APInt.h"
#include "llvm/IR/IRBuilder.h"

namespace pyobfuscator::native::cff {

enum class ScalarMaskDomain { literal, comparison, archive, reference, preparation, local, import_route };
constexpr std::uint32_t preparation_multiplier = 0x27d4eb2du;
constexpr std::uint32_t local_multiplier = 0x9e6c63d1u;
constexpr std::uint32_t import_multiplier = 0xd3a2646du;
std::uint32_t scalar_mask_multiplier(ScalarMaskDomain);

bool supported_scalar_integer(const llvm::Type *type);
llvm::APInt scalar_mask_value(unsigned width, std::uint32_t state, std::uint32_t salt,
                               ScalarMaskDomain domain = ScalarMaskDomain::literal);
llvm::Value *emit_scalar_mask(llvm::IRBuilder<> &builder, llvm::Type *type, llvm::Value *state,
                               std::uint32_t salt,
                               ScalarMaskDomain domain = ScalarMaskDomain::literal);
llvm::Value *emit_scalar_literal(llvm::IRBuilder<> &, const llvm::ConstantInt &, llvm::Value *state_slot,
    std::uint32_t expected_state, std::uint32_t salt);

}  // namespace pyobfuscator::native::cff
