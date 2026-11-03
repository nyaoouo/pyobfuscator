#include "hybrid_scalar_bindings.hpp"
#include "scalar_mask.hpp"
#include "scalar_proof.hpp"
#include "state_layout.hpp"
#include "transition_proof.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
HybridScalarBindings::HybridScalarBindings(const llvm::Function &function, const StateLayout &layout,
    const llvm::AllocaInst *state, const TransitionBinding &delegate, std::uint32_t seed)
    : owner_(&function), state_(const_cast<llvm::AllocaInst *>(state)), delegate_(&delegate) {
    for (const auto &[body, label] : layout.states) {
        const auto *returned = llvm::dyn_cast<llvm::ReturnInst>(body->getTerminator());
        const auto *value = returned == nullptr ? nullptr : llvm::dyn_cast_or_null<llvm::ConstantInt>(returned->getReturnValue());
        if (value == nullptr || !supported_scalar_integer(value->getType())) continue;
        returns_.push_back({const_cast<llvm::ReturnInst *>(returned), const_cast<llvm::BasicBlock *>(body), value,
            std::make_unique<TransitionModel>(function, *value, label, seed)});
    }
}
std::string HybridScalarBindings::verify(const llvm::Function &function) const {
    verified_ = false; operands_.clear();
    if (&function != owner_) return "hybrid scalar owner changed";
    if (const auto reason = delegate_->verify(function); !reason.empty()) return reason;
    const auto *state = llvm::dyn_cast_or_null<llvm::AllocaInst>(state_);
    if (!valid_state_storage(state, &function.getEntryBlock())) return "hybrid scalar state root changed";
    decltype(operands_) operands;
    for (const auto &record : returns_) {
        const auto *returned = llvm::dyn_cast_or_null<llvm::ReturnInst>(record.instruction);
        const auto *body = llvm::dyn_cast_or_null<llvm::BasicBlock>(record.body);
        if (returned == nullptr || body == nullptr || body->getParent() != owner_ || returned->getParent() != body ||
                returned != body->getTerminator() || !record.model->valid()) return "hybrid scalar literal return identity/model changed";
        std::set<const llvm::LoadInst *> reads;
        if (!record.model->match_literal(returned->getReturnValue(), state, *body, reads))
            return "hybrid scalar return lost its exact state-bound literal";
        operands.emplace(returned, std::make_pair(record.original, returned->getReturnValue()));
    }
    operands_ = std::move(operands); verified_ = true; return {};
}
bool HybridScalarBindings::covers_unconditional(const llvm::BasicBlock &body, std::uint32_t state, std::uint32_t normal) const {
    return verified_ && delegate_->covers_unconditional(body, state, normal);
}
const llvm::Value *HybridScalarBindings::normal_encoded(const llvm::BasicBlock &body, const llvm::Value *value) const {
    return verified_ ? delegate_->normal_encoded(body, value) : nullptr;
}
bool HybridScalarBindings::owns_state_read(const llvm::LoadInst &read) const { return verified_ && delegate_->owns_state_read(read); }
bool HybridScalarBindings::owns_state_write(const llvm::StoreInst &write) const { return verified_ && delegate_->owns_state_write(write); }
bool HybridScalarBindings::preserves_terminal_operand(const llvm::Instruction &instruction, unsigned index,
    const llvm::Value *original, const llvm::Value *actual) const {
    const auto found = operands_.find(&instruction);
    return verified_ && index == 0 && instruction.getNumOperands() == 1 && instruction.getOperand(0) == actual &&
        found != operands_.end() && found->second.first == original && found->second.second == actual;
}
}
