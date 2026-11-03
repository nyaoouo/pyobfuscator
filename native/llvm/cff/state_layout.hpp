#pragma once

#include "cff.hpp"

#include <cstdint>
#include <vector>

#include "llvm/ADT/DenseMap.h"

namespace pyobfuscator::native::cff {

struct StateLayout {
    llvm::DenseMap<llvm::BasicBlock *, std::uint32_t> states;
    std::vector<Leaf> sorted_leaves;
    std::uint32_t transition_salt;
    std::uint64_t random_state;
};

std::uint64_t next_random(std::uint64_t &state) noexcept;
StateLayout build_state_layout(llvm::Function &function,
                               llvm::ArrayRef<llvm::BasicBlock *> bodies,
                               unsigned seed);

}  // namespace pyobfuscator::native::cff
