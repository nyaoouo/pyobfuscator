#include "scalar_proof.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

const llvm::BinaryOperator *scalar_operation(const llvm::Value *value, unsigned opcode, const llvm::BasicBlock *body) {
    const auto *operation = llvm::dyn_cast_or_null<llvm::BinaryOperator>(value);
    return operation != nullptr && operation->getOpcode() == opcode && operation->getParent() == body &&
        operation->getType()->isIntegerTy(32) && !operation->hasNoUnsignedWrap() && !operation->hasNoSignedWrap() &&
        !operation->isExact() ? operation : nullptr;
}

bool scalar_constant(const llvm::Value *value, std::uint32_t expected) {
    const auto *constant = llvm::dyn_cast_or_null<llvm::ConstantInt>(value);
    return constant != nullptr && constant->getType()->isIntegerTy(32) && constant->getZExtValue() == expected;
}

namespace {
const llvm::Value *unshift(const llvm::Value *value, unsigned shift, const llvm::BasicBlock *body) {
    const auto *combined = scalar_operation(value, llvm::Instruction::Xor, body);
    const auto *right = combined == nullptr ? nullptr : scalar_operation(combined->getOperand(1), llvm::Instruction::LShr, body);
    return right != nullptr && right->getOperand(0) == combined->getOperand(0) && scalar_constant(right->getOperand(1), shift) ?
        combined->getOperand(0) : nullptr;
}
}  // namespace

const llvm::AllocaInst *match_scalar_mask(const llvm::Value *value, const llvm::BasicBlock &body, std::uint32_t salt,
    std::uint32_t expected, ScalarMaskDomain domain, const char *state_tag, const char *slot_tag) {
    const auto *multiplied = scalar_operation(unshift(value, 13, &body), llvm::Instruction::Mul, &body);
    if (multiplied == nullptr || !scalar_constant(multiplied->getOperand(1), scalar_mask_multiplier(domain))) return nullptr;
    const auto *base = scalar_operation(unshift(multiplied->getOperand(0), 16, &body), llvm::Instruction::Xor, &body);
    const auto *load = base == nullptr ? nullptr : llvm::dyn_cast<llvm::LoadInst>(base->getOperand(0));
    const auto *slot = load == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
    const auto *state = load == nullptr ? nullptr : load->getMetadata(state_tag);
    const auto *number = state == nullptr || state->getNumOperands() != 1 ? nullptr :
        llvm::mdconst::dyn_extract<llvm::ConstantInt>(state->getOperand(0));
    if (base == nullptr || !scalar_constant(base->getOperand(1), salt ^ 0x9e3779b9u) || load == nullptr ||
        !load->isSimple() || load->getParent() != &body || slot == nullptr || !slot->getAllocatedType()->isIntegerTy(32) ||
        slot->getParent() != &body.getParent()->getEntryBlock() || !scalar_constant(number, expected)) return nullptr;
    unsigned slots = 0;
    for (const auto &block : *body.getParent()) for (const auto &instruction : block)
        if (const auto *flag = instruction.getMetadata(slot_tag)) {
            if (&instruction != slot || flag->getNumOperands() != 0) return nullptr;
            ++slots;
        }
    return slots == 1 ? slot : nullptr;
}

}  // namespace pyobfuscator::native::cff
