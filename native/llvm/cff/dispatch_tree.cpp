#include "cff.hpp"
#include "state_layout.hpp"

#include <algorithm>

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"

namespace pyobfuscator::native::cff {

llvm::BasicBlock *build_dispatch_tree(llvm::Function &function, llvm::Value *state,
                                      llvm::ArrayRef<Leaf> leaves,
                                      std::uint64_t &random_state) {
    auto &context = function.getContext();
    if (leaves.size() == 1) {
        auto *leaf = llvm::BasicBlock::Create(context, "pyobf.leaf", &function);
        llvm::IRBuilder<> builder(leaf);
        builder.CreateBr(leaves.front().body);
        return leaf;
    }

    // Keep logarithmic depth while changing the tree topology across builds.
    const auto first = std::max<std::size_t>(1, leaves.size() / 3);
    const auto last = std::min<std::size_t>(leaves.size() - 1,
                                            (leaves.size() * 2 + 2) / 3);
    const auto middle = first + next_random(random_state) % (last - first + 1);
    auto *node = llvm::BasicBlock::Create(context, "pyobf.compare", &function);
    auto *lower = build_dispatch_tree(function, state, leaves.take_front(middle), random_state);
    auto *upper = build_dispatch_tree(function, state, leaves.drop_front(middle), random_state);
    const auto lower_state = leaves[middle - 1].state;
    const auto upper_state = leaves[middle].state;
    const auto gap = static_cast<std::uint64_t>(upper_state) - lower_state;
    const auto pivot = static_cast<std::uint32_t>(
        lower_state + 1 + next_random(random_state) % (gap - 1));
    llvm::IRBuilder<> builder(node);
    builder.CreateCondBr(builder.CreateICmpUGE(state, builder.getInt32(pivot)),
                         upper, lower);
    return node;
}

}  // namespace pyobfuscator::native::cff
