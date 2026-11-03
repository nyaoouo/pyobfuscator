#include "path_fold.hpp"
#include "path_fold/value.hpp"

#include <array>

#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {

void require_word(llvm::Value *value) {
    if (value == nullptr || !value->getType()->isIntegerTy(32))
        llvm::report_fatal_error("path fold needs an i32 value");
}

void require_storage(llvm::Value *storage) {
    if (storage == nullptr || !storage->getType()->isPointerTy())
        llvm::report_fatal_error("path fold needs pointer storage");
}

llvm::Value *rotate(llvm::IRBuilder<> &builder, llvm::Value *value, unsigned count) {
    return builder.CreateOr(builder.CreateShl(value, count), builder.CreateLShr(value, 32 - count));
}

llvm::Value *mix(llvm::IRBuilder<> &builder, llvm::Value *value) {
    value = builder.CreateXor(value, builder.CreateLShr(value, 16));
    value = builder.CreateMul(value, builder.getInt32(0x7feb352du));
    value = builder.CreateXor(value, builder.CreateLShr(value, 15));
    value = builder.CreateMul(value, builder.getInt32(0x846ca68bu));
    return builder.CreateXor(value, builder.CreateLShr(value, 16));
}

llvm::Value *lane(llvm::IRBuilder<> &builder, llvm::Value *storage, unsigned index) {
    return builder.CreateGEP(builder.getInt32Ty(), storage, builder.getInt32(index));
}

llvm::StoreInst *store(llvm::IRBuilder<> &builder, llvm::Value *value, llvm::Value *pointer) {
    auto *instruction = builder.CreateStore(value, pointer);
    instruction->setVolatile(true);
    instruction->setAlignment(llvm::Align(4));
    return instruction;
}

}  // namespace

FoldStores emit_path_fold_initialize(llvm::IRBuilder<> &builder, llvm::Value *storage, llvm::Value *seed) {
    require_storage(storage);
    require_word(seed);
    FoldStores stores{};
    for (unsigned index = 0; index != path_fold::lanes; ++index) {
        auto *input = builder.CreateAdd(seed, builder.getInt32(0x9e3779b9u * (index + 1)));
        stores[index] = store(builder, mix(builder, input), lane(builder, storage, index));
    }
    return stores;
}

FoldStores emit_path_fold_advance(llvm::IRBuilder<> &builder, llvm::Value *storage,
                            llvm::Value *tag, llvm::Value *word) {
    require_storage(storage);
    require_word(tag);
    require_word(word);
    std::array<llvm::Value *, path_fold::lanes> before{}, after{};
    for (unsigned index = 0; index != before.size(); ++index) {
        auto *value = builder.CreateLoad(builder.getInt32Ty(), lane(builder, storage, index), "pyobf.fold.before");
        value->setVolatile(true);
        value->setAlignment(llvm::Align(4));
        before[index] = value;
    }
    auto *event = mix(builder, builder.CreateXor(word, builder.getInt32(0x9e3779b9u)));
    auto *label = mix(builder, builder.CreateXor(tag, builder.getInt32(0xd1b54a35u)));
    for (unsigned index = 0; index != before.size(); ++index) {
        auto *value = builder.CreateAdd(before[index], builder.CreateXor(event, before[(index + 1) % before.size()]));
        value = builder.CreateAdd(value, builder.getInt32(0x9e3779b9u * (index + 1)));
        value = rotate(builder, value, 5 + 3 * index);
        value = builder.CreateXor(value, rotate(builder,
            builder.CreateAdd(before[(index + 3) % before.size()], label), 7));
        after[index] = builder.CreateAdd(value, rotate(builder,
            builder.CreateAdd(builder.CreateAdd(event, before[(index + 5) % before.size()]),
                              rotate(builder, label, 1 + 3 * index)), 13));
    }
    FoldStores stores{};
    for (unsigned index = 0; index != after.size(); ++index)
        stores[index] = store(builder, after[index], lane(builder, storage, index));
    return stores;
}

llvm::Value *emit_path_fold_word(llvm::IRBuilder<> &builder, llvm::Value *current_state,
                                 std::uint32_t encoded, std::uint32_t salt) {
    require_word(current_state);
    return builder.CreateXor(mix(builder, builder.CreateXor(current_state, builder.getInt32(salt))),
                              builder.getInt32(encoded));
}

}  // namespace pyobfuscator::native::cff
