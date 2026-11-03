#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "llvm/IR/ValueHandle.h"

namespace pyobfuscator::native::cff {
struct BogusControlSite {
    llvm::WeakVH guard, normal, decoy, predicate, result, work;
    std::string component, provenance;
    std::uint32_t predicate_salt;
};
using BogusControlPlan = std::vector<BogusControlSite>;
}
