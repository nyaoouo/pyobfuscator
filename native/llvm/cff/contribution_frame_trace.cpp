#include "contribution_edges.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
llvm::Instruction *ContributionEdgePlan::insertion_source(const Edge &edge) const {
    auto *term = llvm::dyn_cast_or_null<llvm::Instruction>(edge.terminator);
    auto *source = llvm::dyn_cast_or_null<llvm::InvokeInst>(term);
    if (source == nullptr) return term;
    for (const auto &invoke : invokes_) if (invoke.source == source) {
        if (materialized_ || invoke.bridge != nullptr || edge.successor != 0 || invoke.normal != edge.target ||
                source->getUnwindDest() != invoke.unwind || source->getNormalDest() != normal_entry(invoke) ||
                !valid_completions(invoke)) return nullptr;
        if (invoke.completions.empty()) return source;
        auto *last = llvm::dyn_cast_or_null<llvm::BasicBlock>(invoke.completions.back());
        return last == nullptr ? nullptr : last->getTerminator();
    }
    return nullptr;
}
const llvm::BasicBlock *ContributionEdgePlan::normal_entry(const Invoke &invoke) const {
    // Original destinations retain existing semantic-normalization aliases;
    // registered source/completion identities must never follow RAUW.
    const llvm::Value *value = invoke.completions.empty() ? static_cast<llvm::Value *>(invoke.normal) :
        static_cast<llvm::Value *>(invoke.completions.front());
    return llvm::dyn_cast_or_null<llvm::BasicBlock>(value);
}
bool ContributionEdgePlan::valid_completions(const Invoke &invoke) const {
    for (unsigned index = 0; index != invoke.completions.size(); ++index) {
        const auto *body = llvm::dyn_cast_or_null<llvm::BasicBlock>(invoke.completions[index]);
        const llvm::Value *next_value = index + 1 == invoke.completions.size() ? static_cast<llvm::Value *>(invoke.normal) :
            static_cast<llvm::Value *>(invoke.completions[index + 1]);
        const auto *next = llvm::dyn_cast_or_null<llvm::BasicBlock>(next_value);
        const auto *branch = body == nullptr ? nullptr : llvm::dyn_cast<llvm::BranchInst>(body->getTerminator());
        if (body == nullptr || body->getParent() != owner_ || next == nullptr || next->getParent() != owner_ ||
                branch == nullptr || !branch->isUnconditional() || branch->getSuccessor(0) != next) return false;
    }
    return true;
}
std::string ContributionEdgePlan::replace_invoke(const llvm::InvokeInst &from, llvm::InvokeInst &to,
    llvm::BasicBlock &completion) {
    if (!failure_.empty()) return failure_;
    for (auto &invoke : invokes_) if (invoke.source == &from) {
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(completion.getTerminator());
        if (&from == &to || from.getFunction() != owner_ || to.getFunction() != owner_ ||
                to.getParent() != from.getParent() || completion.getParent() != owner_ ||
                invoke.bridge != nullptr || !invoke.completions.empty() ||
                from.getNormalDest() != invoke.normal || from.getUnwindDest() != invoke.unwind ||
                to.getNormalDest() != &completion || to.getUnwindDest() != invoke.unwind ||
                branch == nullptr || !branch->isUnconditional() || branch->getSuccessor(0) != invoke.normal)
            return failure_ = "framed contribution invoke changed its frozen source or normal/unwind route";
        // Frame implementation and argument/target ABI remain owned by the module
        // frame verifier. This trace owns source identity and the original gate route.
        invoke.source = &to; invoke.completions.emplace_back(&completion);
        for (auto &edge : edges_) if (edge.origin == &from) edge.terminator = &to;
        return {};
    }
    return failure_ = "framed contribution invoke has no frozen original source";
}
std::string ContributionEdgePlan::completion_split(llvm::BasicBlock &prefix, llvm::BasicBlock &suffix) {
    if (!failure_.empty()) return failure_;
    for (auto &invoke : invokes_) for (unsigned index = 0; index != invoke.completions.size(); ++index) {
        if (invoke.completions[index] != &prefix) continue;
        const llvm::Value *next_value = index + 1 == invoke.completions.size() ? static_cast<llvm::Value *>(invoke.normal) :
            static_cast<llvm::Value *>(invoke.completions[index + 1]);
        const auto *next = llvm::dyn_cast_or_null<llvm::BasicBlock>(next_value);
        const auto *before = llvm::dyn_cast<llvm::BranchInst>(prefix.getTerminator());
        const auto *after = llvm::dyn_cast<llvm::BranchInst>(suffix.getTerminator());
        bool used = false;
        for (const auto &other : invokes_) for (const auto &body : other.completions) used |= body == &suffix;
        if (prefix.getParent() != owner_ || suffix.getParent() != owner_ || used || next == nullptr ||
                before == nullptr || !before->isUnconditional() || before->getSuccessor(0) != &suffix ||
                after == nullptr || !after->isUnconditional() || after->getSuccessor(0) != next)
            return failure_ = "framed contribution completion split changed its frozen continuation";
        invoke.completions.insert(invoke.completions.begin() + index + 1, llvm::WeakVH(&suffix));
        return {};
    }
    return {};
}
}
