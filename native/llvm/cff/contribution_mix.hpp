#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "llvm/IR/IRBuilder.h"

namespace pyobfuscator::native::cff {
struct ContributionMixPlan {
    enum class Kind { literal, input, operation };
    struct Node {
        Kind kind;
        std::uint32_t value;
        unsigned opcode = 0, left = 0, right = 0;
    };
    std::vector<Node> nodes;
    unsigned root = 0, inputs = 0;
};
ContributionMixPlan plan_contribution_mix(std::uint32_t domain, std::uint32_t function,
    std::uint32_t site, llvm::ArrayRef<std::pair<std::uint32_t, std::uint32_t>> labels);
llvm::Value *emit_contribution_mix(llvm::IRBuilder<> &, const ContributionMixPlan &, llvm::ArrayRef<llvm::Value *>);
bool match_contribution_mix(const llvm::Value *, const ContributionMixPlan &,
    llvm::ArrayRef<const llvm::Value *>, const llvm::BasicBlock &);
}
