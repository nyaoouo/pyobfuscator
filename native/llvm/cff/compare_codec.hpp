#pragma once

#include "scalar_mask.hpp"

namespace pyobfuscator::native::cff {

struct CompareCodec {
    llvm::APInt addend;
    llvm::APInt first_multiplier;
    llvm::APInt second_multiplier;
    unsigned first_shift;
    unsigned second_shift;
    unsigned third_shift;
};

CompareCodec make_compare_codec(unsigned width, std::uint32_t salt);
llvm::APInt encode_comparison(llvm::APInt value, const llvm::APInt &key, const CompareCodec &codec);
llvm::Value *emit_comparison(llvm::IRBuilder<> &builder, llvm::Value *value,
                              llvm::Value *key, const CompareCodec &codec);

}  // namespace pyobfuscator::native::cff
