#include "contribution_edges.hpp"

#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
void ContributionEdgePlan::invoke_lowered(const llvm::InvokeInst &source, llvm::BasicBlock &bridge) {
    for (auto &invoke : invokes_) {
        if (invoke.source != &source) continue;
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(bridge.getTerminator());
        if (invoke.bridge != nullptr || source.getNormalDest() != &bridge || source.getUnwindDest() != invoke.unwind ||
                branch == nullptr || !branch->isUnconditional() || branch->getSuccessor(0) != normal_entry(invoke) ||
                !valid_completions(invoke)) {
            failure_ = "automatic invoke lowering changed its frozen normal/unwind route";
            return;
        }
        invoke.bridge = &bridge;
        return;
    }
}

bool ContributionEdgePlan::source_targets_gateway(const Edge &edge) const {
    const auto *term = llvm::dyn_cast_or_null<llvm::Instruction>(edge.terminator);
    if (term == nullptr || !term->isTerminator() || edge.successor >= term->getNumSuccessors()) return false;
    const auto *source = llvm::dyn_cast<llvm::InvokeInst>(term);
    if (source == nullptr) return term->getSuccessor(edge.successor) == edge.gateway;
    for (const auto &invoke : invokes_) {
        if (invoke.source != source) continue;
        const auto *bridge = llvm::dyn_cast_or_null<llvm::BasicBlock>(invoke.bridge);
        const auto *branch = bridge == nullptr ? nullptr : llvm::dyn_cast<llvm::BranchInst>(bridge->getTerminator());
        return source->getParent()->getTerminator() == source && edge.successor == 0 && invoke.normal == edge.gateway && source->getNormalDest() == bridge &&
            source->getUnwindDest() == invoke.unwind && branch != nullptr && branch->isUnconditional() &&
            branch->getSuccessor(0) == normal_entry(invoke) && valid_completions(invoke);
    }
    return false;
}
}
