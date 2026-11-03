#pragma once

#include "llvm/IR/ValueHandle.h"
#include <cstdint>
#include <string>
#include <map>
#include <set>
#include <vector>

namespace llvm { class Function; class BasicBlock; class AllocaInst; }
namespace pyobfuscator::native::cff {
struct StateLayout;
class TransitionBinding;
struct FlowBoundary {
    const llvm::BasicBlock *setup = nullptr, *exit_leaf = nullptr, *exit = nullptr;
};
class ContributionEdgeFlowSeal {
public:
    ContributionEdgeFlowSeal(const llvm::Function &, const StateLayout &, const llvm::AllocaInst *, const llvm::BasicBlock *, FlowBoundary = {});
    std::string verify(const llvm::Function &, const TransitionBinding * = nullptr) const;
private:
    struct Jump {
        const llvm::BasicBlock *body;
        llvm::WeakTrackingVH condition;
        std::uint32_t yes, no;
        std::uint32_t state;
    };
    const llvm::Function *owner_;
    const llvm::AllocaInst *state_;
    const llvm::BasicBlock *dispatch_;
    FlowBoundary boundary_;
    std::uint32_t salt_;
    std::vector<Jump> jumps_;
    std::map<const llvm::BasicBlock *, std::uint32_t> states_;
    std::set<const llvm::BasicBlock *> original_;
    std::vector<llvm::WeakTrackingVH> terminals_;
    std::uint32_t initial_ = 0;
};
}
