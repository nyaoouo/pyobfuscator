#include "cfg_origin.hpp"

#include <set>

#include "llvm/IR/Function.h"

namespace pyobfuscator::native::cff {

const char *role_name(BlockRole role) {
    switch (role) {
    case BlockRole::real: return "real";
    case BlockRole::shape: return "shape";
    case BlockRole::routing: return "routing";
    case BlockRole::decoy: return "decoy";
    case BlockRole::junk: return "junk";
    }
    return "invalid";
}

void CfgOrigins::set(const llvm::BasicBlock &block, BlockRole role) { roles_[&block] = role; }

BlockRole CfgOrigins::get(const llvm::BasicBlock &block) const {
    const auto found = roles_.find(&block);
    return found == roles_.end() ? BlockRole::real : found->second;
}

std::string CfgOrigins::validate_new_blocks(const llvm::Function &function,
                                           const std::vector<const llvm::BasicBlock *> &before) const {
    const std::set<const llvm::BasicBlock *> previous(before.begin(), before.end());
    for (const auto &block : function)
        if (!previous.count(&block) && !roles_.count(&block))
            return "prepare hook created a block without an explicit origin";
    return {};
}

}  // namespace pyobfuscator::native::cff
