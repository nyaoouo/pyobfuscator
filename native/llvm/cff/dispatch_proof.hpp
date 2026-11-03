#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace llvm { class AllocaInst; class BasicBlock; class Function; }

namespace pyobfuscator::native::cff {

std::string verify_dispatch_graph(const llvm::Function &, const llvm::AllocaInst *, const llvm::BasicBlock *,
    const std::map<const llvm::BasicBlock *, std::uint32_t> &states,
    const std::set<const llvm::BasicBlock *> &original, std::set<const llvm::BasicBlock *> &tree);

}  // namespace pyobfuscator::native::cff
