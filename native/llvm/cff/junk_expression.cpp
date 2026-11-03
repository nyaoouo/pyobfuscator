#include "junk_expression.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {

std::uint32_t junk_mix_value(std::uint32_t value, std::uint32_t salt, unsigned rounds) {
    for (unsigned index = 0; index < rounds; ++index) {
        const auto key = salt + index * 0x9e3779b9u;
        const auto rotation = key % 31u + 1u;
        value ^= key;
        value = (value >> rotation) | (value << (32u - rotation));
        value *= (key ^ 0x27d4eb2du) | 0x13579bd1u;
        value ^= value >> 16;
    }
    return value;
}

llvm::Value *emit_junk_mix(llvm::IRBuilder<> &builder, llvm::Value *value,
                             std::uint32_t salt, unsigned rounds) {
    for (unsigned index = 0; index < rounds; ++index) {
        const auto key = salt + index * 0x9e3779b9u;
        const auto rotation = key % 31u + 1u;
        value = builder.CreateXor(value, builder.getInt32(key));
        value = builder.CreateOr(builder.CreateLShr(value, rotation),
                                  builder.CreateShl(value, 32u - rotation), "pyobf.junk.rotate");
        value = builder.CreateMul(value, builder.getInt32((key ^ 0x27d4eb2du) | 0x13579bd1u),
                                   "pyobf.junk.multiply");
        // Public diversity coefficients also serve as bounded final-image retention evidence.
        // Original user/donor literals remain eligible for the later scalar transformation.
        llvm::cast<llvm::Instruction>(value)->setMetadata("pyobf.cff.public-coefficient",
            llvm::MDNode::get(builder.getContext(), {}));
        value = builder.CreateXor(value, builder.CreateLShr(value, 16), "pyobf.junk.mix");
    }
    return value;
}

}  // namespace pyobfuscator::native::cff
