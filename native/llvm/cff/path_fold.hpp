#pragma once

#include <cstdint>
#include <array>

#include "llvm/IR/IRBuilder.h"

namespace pyobfuscator::native::cff {
using FoldStores = std::array<llvm::StoreInst *, 8>;

// Storage is eight aligned i32 words owned by one invocation. Volatile accesses
// preserve the runtime dependency; they do not provide inter-thread synchronization.
FoldStores emit_path_fold_initialize(llvm::IRBuilder<> &, llvm::Value *storage, llvm::Value *seed);
FoldStores emit_path_fold_advance(llvm::IRBuilder<> &, llvm::Value *storage,
                            llvm::Value *tag, llvm::Value *word);
llvm::Value *emit_path_fold_word(llvm::IRBuilder<> &, llvm::Value *current_state,
                                 std::uint32_t encoded, std::uint32_t salt);

}  // namespace pyobfuscator::native::cff
