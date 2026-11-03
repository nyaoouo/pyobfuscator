#include "cff.hpp"
#include "region.hpp"

#include "llvm/ADT/StringRef.h"

namespace pyobfuscator::native::cff {

extern const Strategy relative_tree_strategy;
extern const Strategy relative_tree_deep_strategy;
extern const RegionStrategy relative_tree_region_strategy;

const Strategy *find_strategy(llvm::StringRef name) {
    const Strategy *strategies[]{&relative_tree_strategy, &relative_tree_deep_strategy};
    for (const auto *strategy : strategies) {
        if (name == strategy->name) {
            return strategy;
        }
    }
    return nullptr;
}

const RegionStrategy *find_region_strategy(llvm::StringRef name) {
    return name == relative_tree_region_strategy.name ? &relative_tree_region_strategy : nullptr;
}

}  // namespace pyobfuscator::native::cff
