#pragma once

#include "transition_binding.hpp"
#include "transition_model.hpp"
#include "llvm/IR/ValueHandle.h"

#include <map>
#include <vector>

namespace llvm { class AllocaInst; class ConstantInt; class Instruction; }
namespace pyobfuscator::native::cff {
struct StateLayout;

class HybridScalarBindings : public TransitionBinding {
public:
    HybridScalarBindings(const llvm::Function &, const StateLayout &, const llvm::AllocaInst *,
        const TransitionBinding &, std::uint32_t literal_seed);
    std::string verify(const llvm::Function &) const override;
    bool covers_unconditional(const llvm::BasicBlock &, std::uint32_t, std::uint32_t) const override;
    const llvm::Value *normal_encoded(const llvm::BasicBlock &, const llvm::Value *) const override;
    bool owns_state_read(const llvm::LoadInst &) const override;
    bool owns_state_write(const llvm::StoreInst &) const override;
    bool preserves_terminal_operand(const llvm::Instruction &, unsigned, const llvm::Value *, const llvm::Value *) const override;
private:
    struct Return {
        llvm::WeakVH instruction, body;
        const llvm::ConstantInt *original;
        std::unique_ptr<TransitionModel> model;
    };
    const llvm::Function *owner_;
    llvm::WeakVH state_;
    const TransitionBinding *delegate_;
    std::vector<Return> returns_;
    mutable bool verified_ = false;
    mutable std::map<const llvm::Instruction *, std::pair<const llvm::Value *, const llvm::Value *>> operands_;
};
}
