#include "contribution_groups.hpp"
#include "contribution_query.hpp"

#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
std::vector<const llvm::CallInst *> contribution_group_queries(const llvm::BasicBlock &body) {
    std::vector<const llvm::CallInst *> result;
    for (const auto &instruction : body) {
        const auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
        const auto *target = call == nullptr ? nullptr : call->getCalledFunction();
        if (target != nullptr && reserved_contribution_query(target->getName())) result.push_back(call);
    }
    return result;
}
}
