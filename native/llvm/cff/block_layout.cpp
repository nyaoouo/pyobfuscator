#include "cff.hpp"
#include "state_layout.hpp"

#include <algorithm>
#include <cstddef>
#include <vector>

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"

namespace pyobfuscator::native::cff {

void shuffle_body_layout(llvm::Function &function,
                         llvm::ArrayRef<llvm::BasicBlock *> bodies,
                         std::uint64_t &random_state) {
    std::vector<llvm::BasicBlock *> order(bodies.begin(), bodies.end());
    for (std::size_t remaining = order.size(); remaining > 1; --remaining) {
        const auto selected = next_random(random_state) % remaining;
        std::swap(order[remaining - 1], order[selected]);
    }
    auto *anchor = &function.getEntryBlock();
    for (auto *body : order) {
        body->moveAfter(anchor);
        anchor = body;
    }
}

}  // namespace pyobfuscator::native::cff
