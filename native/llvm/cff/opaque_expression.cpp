#include "opaque_expression.hpp"

namespace pyobfuscator::native::cff {

llvm::Value *emit_opaque_true(llvm::IRBuilder<> &builder, llvm::Value *state_slot,
                               std::uint32_t salt, unsigned family) {
    auto *first = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.opaque.first");
    auto *second = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.opaque.second");
    first->setVolatile(true);
    second->setVolatile(true);
    auto *x = builder.CreateXor(first, builder.getInt32(salt));
    auto *y = builder.CreateXor(second, builder.getInt32(salt));
    // The private slot is unchanged between reads on valid execution. Modulo 2/4
    // identities survive u32 wrap; the Python cube/mod-6 identity would not.
    llvm::Value *value;
    if (family % 3 == 0) {
        value = builder.CreateAdd(builder.CreateMul(x, y), x);
        value = builder.CreateAnd(value, builder.getInt32(1));
        return builder.CreateICmpULT(value, builder.getInt32(1), "pyobf.opaque.guard");
    }
    if (family % 3 == 1) {
        value = builder.CreateAnd(builder.CreateMul(x, y), builder.getInt32(3));
        return builder.CreateICmpULT(value, builder.getInt32(2), "pyobf.opaque.guard");
    }
    value = builder.CreateMul(builder.CreateAdd(x, builder.getInt32(1)),
                               builder.CreateAdd(y, builder.getInt32(2)));
    value = builder.CreateAnd(value, builder.getInt32(1));
    return builder.CreateICmpULT(value, builder.getInt32(1), "pyobf.opaque.guard");
}

}  // namespace pyobfuscator::native::cff
