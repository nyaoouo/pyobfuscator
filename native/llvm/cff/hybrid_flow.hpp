#pragma once

#include "hybrid_eh.hpp"

#include <cstdint>
#include <map>

namespace llvm { class Instruction; }

namespace pyobfuscator::native::cff {
class TransitionBinding;

class HybridFlowSeal {
public:
    HybridFlowSeal(const llvm::Function &, const HybridEhPlan &, const StateLayout &,
                    const llvm::AllocaInst *, const llvm::BasicBlock *dispatch);
    std::string verify(const llvm::Function &, const TransitionBinding * = nullptr) const;

private:
    struct Normal {
        const llvm::BasicBlock *body, *yes, *no;
        const llvm::Value *condition;
        const llvm::Constant *constant_condition;
    };
    struct Invoke {
        const llvm::InvokeInst *instruction;
        const llvm::BasicBlock *source, *normal, *unwind, *gateway, *continuation;
    };
    struct Pad { const llvm::BasicBlock *header, *continuation; };
    struct Terminal { const llvm::Instruction *identity; std::vector<const llvm::Value *> operands; };
    const llvm::Function *owner_;
    const llvm::AllocaInst *state_, *correction_;
    const llvm::BasicBlock *dispatch_;
    std::uint32_t salt_, initial_ = 0;
    std::string error_;
    std::map<const llvm::BasicBlock *, std::uint32_t> states_;
    std::set<const llvm::BasicBlock *> original_;
    std::vector<Normal> normal_;
    std::vector<Invoke> invokes_;
    std::vector<Pad> pads_;
    std::map<const llvm::BasicBlock *, Terminal> terminals_;
};

}  // namespace pyobfuscator::native::cff
