#include "state_layout.hpp"

#include <algorithm>
#include <set>

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Function.h"

namespace pyobfuscator::native::cff {

std::uint64_t next_random(std::uint64_t &state) noexcept {
    state += 0x9e3779b97f4a7c15ull;
    auto value = state;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31);
}

namespace {

std::uint64_t stable_name_hash(llvm::StringRef name) noexcept {
    std::uint64_t hash = 0xcbf29ce484222325ull;
    for (const unsigned char character : name.bytes()) {
        hash = (hash ^ character) * 0x100000001b3ull;
    }
    return hash;
}

bool separated_from_existing(const std::set<std::uint32_t> &used,
                             std::uint32_t candidate) noexcept {
    if (candidate < 4 || candidate > UINT32_MAX - 4) {
        return false;
    }
    const auto next = used.lower_bound(candidate);
    if (next != used.end() && *next - candidate < 4) {
        return false;
    }
    if (next != used.begin() && candidate - *std::prev(next) < 4) {
        return false;
    }
    return true;
}

}  // namespace

StateLayout build_state_layout(llvm::Function &function,
                               llvm::ArrayRef<llvm::BasicBlock *> bodies,
                               unsigned seed) {
    StateLayout layout;
    layout.random_state = (static_cast<std::uint64_t>(seed) << 32) ^
                          stable_name_hash(function.getName());
    layout.transition_salt = static_cast<std::uint32_t>(next_random(layout.random_state)) | 1u;
    std::set<std::uint32_t> used;
    for (auto *body : bodies) {
        std::uint32_t state;
        do {
            state = static_cast<std::uint32_t>(next_random(layout.random_state));
        } while (!separated_from_existing(used, state));
        used.insert(state);
        layout.states[body] = state;
        layout.sorted_leaves.push_back({state, body});
    }
    std::sort(layout.sorted_leaves.begin(), layout.sorted_leaves.end(),
              [](const Leaf &left, const Leaf &right) { return left.state < right.state; });
    return layout;
}

}  // namespace pyobfuscator::native::cff
