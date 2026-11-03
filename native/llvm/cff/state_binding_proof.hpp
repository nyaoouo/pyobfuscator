#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace llvm { class Function; class AllocaInst; class BasicBlock; }
namespace pyobfuscator::native::cff {
std::string verify_state_bindings(const llvm::Function &, const llvm::AllocaInst *,
    const std::map<const llvm::BasicBlock *, std::uint32_t> &states);
}
