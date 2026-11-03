#pragma once

#include <cstdint>
#include <optional>

namespace llvm { class AllocaInst; class BasicBlock; class LoadInst; class StoreInst; class Value; }

namespace pyobfuscator::native::cff {

struct StateUpdate {
    const llvm::StoreInst *store;
    const llvm::LoadInst *current;
    const llvm::Value *encoded;
};

bool valid_state_storage(const llvm::AllocaInst *, const llvm::BasicBlock *entry);
bool simple_state_read(const llvm::LoadInst *, const llvm::AllocaInst *, const llvm::BasicBlock *);
std::optional<StateUpdate> match_state_update(const llvm::BasicBlock &, const llvm::AllocaInst *,
                                              std::uint32_t salt, const llvm::BasicBlock *dispatch);

}  // namespace pyobfuscator::native::cff
