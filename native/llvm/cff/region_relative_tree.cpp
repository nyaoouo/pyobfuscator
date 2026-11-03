#include "region.hpp"

namespace pyobfuscator::native::cff {

extern const RegionStrategy relative_tree_region_strategy{
    "relative-tree-region", validate_relative_tree_region, flatten_region};

}  // namespace pyobfuscator::native::cff
