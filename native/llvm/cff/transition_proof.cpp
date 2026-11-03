#include "transition_proof.hpp"
#include "scalar_proof.hpp"

#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {

const llvm::Value *unshift(const llvm::Value *value, unsigned shift, const llvm::BasicBlock *body) {
    const auto *combined = scalar_operation(value, llvm::Instruction::Xor, body);
    const auto *right = combined == nullptr ? nullptr : scalar_operation(combined->getOperand(1), llvm::Instruction::LShr, body);
    return right != nullptr && right->getOperand(0) == combined->getOperand(0) &&
        scalar_constant(right->getOperand(1), shift) ? combined->getOperand(0) : nullptr;
}

bool runtime_mask(const llvm::Value *value, const llvm::LoadInst *current,
                    std::uint32_t salt, const llvm::BasicBlock *body) {
    const auto *second = scalar_operation(unshift(value, 16, body), llvm::Instruction::Mul, body);
    if (second == nullptr || !scalar_constant(second->getOperand(1), 0x846ca68bu)) return false;
    const auto *first = scalar_operation(unshift(second->getOperand(0), 15, body), llvm::Instruction::Mul, body);
    if (first == nullptr || !scalar_constant(first->getOperand(1), 0x7feb352du)) return false;
    const auto *base = scalar_operation(unshift(first->getOperand(0), 16, body), llvm::Instruction::Xor, body);
    return base != nullptr && base->getOperand(0) == current && scalar_constant(base->getOperand(1), salt);
}

}  // namespace

bool valid_state_storage(const llvm::AllocaInst *slot, const llvm::BasicBlock *entry) {
    const auto *count = slot == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(slot->getArraySize());
    return slot != nullptr && slot->getParent() == entry && slot->getAddressSpace() == 0 &&
        slot->getAllocatedType()->isIntegerTy(32) && count != nullptr && count->isOne() && slot->getAlign().value() == 4;
}

bool simple_state_read(const llvm::LoadInst *read, const llvm::AllocaInst *slot, const llvm::BasicBlock *body) {
    return read != nullptr && read->getParent() == body && read->getPointerOperand() == slot &&
        read->isSimple() && read->getType()->isIntegerTy(32) && read->getAlign() == slot->getAlign() &&
        !read->hasPoisonGeneratingAnnotations();
}

std::optional<StateUpdate> match_state_update(const llvm::BasicBlock &body, const llvm::AllocaInst *slot,
                                              std::uint32_t salt, const llvm::BasicBlock *dispatch) {
    const auto *branch = llvm::dyn_cast<llvm::BranchInst>(body.getTerminator());
    const auto *store = branch == nullptr ? nullptr : llvm::dyn_cast_or_null<llvm::StoreInst>(branch->getPrevNode());
    if (branch == nullptr || !branch->isUnconditional() || branch->getSuccessor(0) != dispatch ||
        store == nullptr || !store->isSimple() || store->getPointerOperand() != slot || store->getAlign() != slot->getAlign()) return {};
    const auto *sum = scalar_operation(store->getValueOperand(), llvm::Instruction::Add, &body);
    const auto *current = sum == nullptr ? nullptr : llvm::dyn_cast<llvm::LoadInst>(sum->getOperand(0));
    const auto *delta = sum == nullptr ? nullptr : scalar_operation(sum->getOperand(1), llvm::Instruction::Xor, &body);
    if (!simple_state_read(current, slot, &body) || delta == nullptr ||
        !runtime_mask(delta->getOperand(1), current, salt, &body)) return {};
    return StateUpdate{store, current, delta->getOperand(0)};
}

}  // namespace pyobfuscator::native::cff
