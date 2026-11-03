#include "transition_encode.hpp"

namespace pyobfuscator::native::cff {

namespace {

std::uint32_t state_mask(std::uint32_t state, std::uint32_t salt) noexcept {
    auto value = state ^ salt;
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value;
}

llvm::Value *runtime_mask(llvm::IRBuilder<> &builder, llvm::Value *current,
                          std::uint32_t salt) {
    llvm::Value *value = builder.CreateXor(current, builder.getInt32(salt));
    value = builder.CreateXor(value, builder.CreateLShr(value, builder.getInt32(16)));
    value = builder.CreateMul(value, builder.getInt32(0x7feb352du));
    value = builder.CreateXor(value, builder.CreateLShr(value, builder.getInt32(15)));
    value = builder.CreateMul(value, builder.getInt32(0x846ca68bu));
    return builder.CreateXor(value, builder.CreateLShr(value, builder.getInt32(16)));
}

}  // namespace

std::uint32_t encode_delta(std::uint32_t source, std::uint32_t target,
                           std::uint32_t salt) noexcept {
    return (target - source) ^ state_mask(source, salt);
}

llvm::Value *decode_delta(llvm::IRBuilder<> &builder, llvm::Value *current,
                          llvm::Value *encoded, std::uint32_t salt) {
    return builder.CreateXor(encoded, runtime_mask(builder, current, salt));
}

}  // namespace pyobfuscator::native::cff
