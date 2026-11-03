#include "scalar_mask.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {
std::uint32_t scalar_mask_multiplier(ScalarMaskDomain domain) {
    return domain == ScalarMaskDomain::literal ? 0x85ebca6bu :
        domain == ScalarMaskDomain::comparison ? 0xd168aaadu :
        domain == ScalarMaskDomain::archive ? 0xc2b2ae35u :
        domain == ScalarMaskDomain::reference ? 0x165667b1u :
        domain == ScalarMaskDomain::preparation ? preparation_multiplier :
        domain == ScalarMaskDomain::import_route ? import_multiplier : local_multiplier;
}

namespace {
std::uint32_t lane_mask(std::uint32_t state, std::uint32_t salt, ScalarMaskDomain domain) {
    auto value = state ^ salt ^ 0x9e3779b9u;
    value ^= value >> 16;
    value *= scalar_mask_multiplier(domain);
    value ^= value >> 13;
    return value;
}

}  // namespace

bool supported_scalar_integer(const llvm::Type *type) {
    return type->isIntegerTy() && type->getIntegerBitWidth() <= 128;
}

llvm::Value *emit_scalar_literal(llvm::IRBuilder<> &builder, const llvm::ConstantInt &constant,
    llvm::Value *state_slot, std::uint32_t expected_state, std::uint32_t salt) {
    auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.literal.state");
    auto *mask = emit_scalar_mask(builder, constant.getType(), state, salt);
    const auto encoded = constant.getValue() ^ scalar_mask_value(constant.getBitWidth(), expected_state, salt);
    return builder.CreateXor(llvm::ConstantInt::get(constant.getType(), encoded), mask, "pyobf.literal.decode");
}

llvm::APInt scalar_mask_value(unsigned width, std::uint32_t state, std::uint32_t salt,
                               ScalarMaskDomain domain) {
    llvm::APInt result(width, 0);
    for (unsigned offset = 0; offset < width; offset += 32) {
        const auto word = lane_mask(state, salt + (offset / 32) * 0x9e3779b9u, domain);
        result |= llvm::APInt(32, word).zextOrTrunc(width).shl(offset);
    }
    return result;
}

llvm::Value *emit_scalar_mask(llvm::IRBuilder<> &builder, llvm::Type *type, llvm::Value *state,
                               std::uint32_t salt, ScalarMaskDomain domain) {
    llvm::Value *result = nullptr;
    const auto width = type->getIntegerBitWidth();
    for (unsigned offset = 0; offset < width; offset += 32) {
        const auto lane_salt = salt + (offset / 32) * 0x9e3779b9u;
        auto *value = builder.CreateXor(state, builder.getInt32(lane_salt ^ 0x9e3779b9u));
        value = builder.CreateXor(value, builder.CreateLShr(value, 16));
        value = builder.CreateMul(value, builder.getInt32(scalar_mask_multiplier(domain)));
        llvm::cast<llvm::Instruction>(value)->setMetadata("pyobf.cff.public-coefficient",
            llvm::MDNode::get(builder.getContext(), {}));
        value = builder.CreateXor(value, builder.CreateLShr(value, 13));
        value = builder.CreateZExtOrTrunc(value, type);
        if (offset != 0) value = builder.CreateShl(value, llvm::ConstantInt::get(type, offset));
        result = result == nullptr ? value : builder.CreateOr(result, value);
    }
    return result;
}

}  // namespace pyobfuscator::native::cff
