#include "compare_codec.hpp"

#include <algorithm>

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {

CompareCodec make_compare_codec(unsigned width, std::uint32_t salt) {
    auto first = scalar_mask_value(width, 0xa17c9e35u, salt ^ 0x11f5a8bdu);
    auto second = scalar_mask_value(width, 0x8e0d32b7u, salt ^ 0x67c49f03u);
    first.setBit(0);
    second.setBit(0);
    return {scalar_mask_value(width, 0x23ab751du, salt ^ 0x93b6e04fu), first, second,
            std::max(1u, width / 2), std::max(1u, width / 3), std::max(1u, width / 2 + width / 8)};
}

llvm::APInt encode_comparison(llvm::APInt value, const llvm::APInt &key, const CompareCodec &codec) {
    value = (value ^ key) + codec.addend;
    value = (value ^ value.lshr(codec.first_shift)) * codec.first_multiplier;
    value = (value ^ value.lshr(codec.second_shift)) * codec.second_multiplier;
    return value ^ value.lshr(codec.third_shift);
}

llvm::Value *emit_comparison(llvm::IRBuilder<> &builder, llvm::Value *value,
                              llvm::Value *key, const CompareCodec &codec) {
    auto *type = value->getType();
    value = builder.CreateAdd(builder.CreateXor(value, key), llvm::ConstantInt::get(type, codec.addend));
    const auto step = [&](llvm::Value *input, unsigned shift, const llvm::APInt &coefficient) {
        auto *mixed = builder.CreateXor(input, builder.CreateLShr(input, llvm::ConstantInt::get(type, shift)));
        auto *product = builder.CreateMul(mixed, llvm::ConstantInt::get(type, coefficient), "pyobf.compare.product");
        llvm::cast<llvm::Instruction>(product)->setMetadata("pyobf.cff.public-coefficient",
            llvm::MDNode::get(builder.getContext(), {}));
        return product;
    };
    value = step(value, codec.first_shift, codec.first_multiplier);
    value = step(value, codec.second_shift, codec.second_multiplier);
    return builder.CreateXor(value, builder.CreateLShr(value, llvm::ConstantInt::get(type, codec.third_shift)),
                              "pyobf.compare.encode");
}

}  // namespace pyobfuscator::native::cff
