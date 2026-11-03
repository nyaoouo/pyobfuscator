#include "call_preparation.hpp"
#include "scalar_mask.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {
namespace {

const llvm::BinaryOperator *operation(const llvm::Value *value, unsigned opcode, const llvm::BasicBlock *body) {
    const auto *result = llvm::dyn_cast_or_null<llvm::BinaryOperator>(value);
    return result != nullptr && result->getOpcode() == opcode && result->getParent() == body &&
        result->getType()->isIntegerTy(32) && !result->hasNoUnsignedWrap() && !result->hasNoSignedWrap() &&
        !result->isExact() ? result : nullptr;
}

bool constant(const llvm::Value *value, std::uint32_t expected) {
    const auto *number = llvm::dyn_cast<llvm::ConstantInt>(value);
    return number != nullptr && number->getType()->isIntegerTy(32) && number->getZExtValue() == expected;
}

const llvm::Value *unshift(const llvm::Value *value, unsigned shift, const llvm::BasicBlock *body) {
    const auto *combined = operation(value, llvm::Instruction::Xor, body);
    const auto *right = combined == nullptr ? nullptr : operation(combined->getOperand(1), llvm::Instruction::LShr, body);
    return right != nullptr && right->getOperand(0) == combined->getOperand(0) && constant(right->getOperand(1), shift) ?
        combined->getOperand(0) : nullptr;
}

}  // namespace

std::optional<FramePlacement> frame_placement(const llvm::DataLayout &data, const FrameLayout &layout, unsigned field) {
    if (layout.padding == ~0u || field >= layout.type->getNumElements() || field == layout.padding || layout.type->isPacked()) return {};
    auto *type = layout.type->getElementType(field);
    const auto size = data.getTypeAllocSize(type).getFixedValue();
    const auto total = data.getTypeAllocSize(layout.type).getFixedValue();
    const auto alignment = data.getABITypeAlign(type).value();
    const auto offset = data.getStructLayout(layout.type)->getElementOffset(field);
    if (!size || total >= (1ull << 31) || size > total || offset % alignment) return {};
    const auto placements = (total - size) / alignment + 1;
    if (placements < 2 || placements >= (1ull << 31)) return {};
    return FramePlacement{static_cast<unsigned>(offset), static_cast<unsigned>(alignment), static_cast<unsigned>(placements)};
}

std::optional<unsigned> prepared_frame_field(const llvm::GetElementPtrInst &address, const llvm::Value *root,
                                             const FrameLayout &layout) {
    const auto *tag = address.getMetadata("pyobf.prep.bound");
    const auto *descriptor = tag != nullptr && tag->getNumOperands() == 4 ? llvm::dyn_cast<llvm::MDNode>(tag->getOperand(0)) : nullptr;
    const auto info = read_frame_metadata(descriptor);
    const auto field = frame_number(tag, 1), salt = frame_number(tag, 2), expected = frame_number(tag, 3);
    const auto placement = field ? frame_placement(address.getModule()->getDataLayout(), layout, *field) : std::optional<FramePlacement>{};
    if (!info || info->layout.type != layout.type || !field || !salt || !expected || !placement ||
        address.getPointerOperand() != root || !address.getSourceElementType()->isIntegerTy(8) ||
        address.getNumIndices() != 1 || address.isInBounds()) return {};
    const auto *body = address.getParent();
    const auto *offset = operation(address.getOperand(1), llvm::Instruction::Mul, body);
    const auto *bounded = offset == nullptr ? nullptr : operation(offset->getOperand(0), llvm::Instruction::URem, body);
    if (offset == nullptr || bounded == nullptr || !constant(offset->getOperand(1), placement->alignment) ||
        !constant(bounded->getOperand(1), placement->placements)) return {};
    const auto encoded = (placement->offset / placement->alignment) ^ static_cast<std::uint32_t>(
        scalar_mask_value(32, *expected, *salt, ScalarMaskDomain::preparation).getZExtValue());
    const auto *decoded = operation(bounded->getOperand(0), llvm::Instruction::Xor, body);
    if (decoded == nullptr || !constant(decoded->getOperand(1), encoded)) return {};
    const auto *multiplied = operation(unshift(decoded->getOperand(0), 13, body),
        llvm::Instruction::Mul, body);
    if (multiplied == nullptr || !constant(multiplied->getOperand(1), preparation_multiplier)) return {};
    const auto *unshifted = unshift(multiplied->getOperand(0), 16, body);
    const auto *base = operation(unshifted, llvm::Instruction::Xor, body);
    const auto folded_salt = *salt ^ 0x9e3779b9u;
    const auto *load = base == nullptr ? nullptr : llvm::dyn_cast<llvm::LoadInst>(base->getOperand(0));
    const auto *slot = load == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
    if (base == nullptr || !constant(base->getOperand(1), folded_salt) || load == nullptr ||
        !load->isSimple() || load->getParent() != body || slot == nullptr || !slot->getAllocatedType()->isIntegerTy(32) ||
        slot->getParent() != &address.getFunction()->getEntryBlock() || frame_number(load->getMetadata("pyobf.prep.state"), 0) != expected)
        return {};
    unsigned slots = 0;
    for (const auto &block : *address.getFunction()) for (const auto &instruction : block)
        if (const auto *flag = instruction.getMetadata("pyobf.prep.state-slot")) {
            if (&instruction != slot || flag->getNumOperands() != 0) return {};
            ++slots;
        }
    return slots == 1 && preparation_state_routes_to(*body, slot, *expected) ? field : std::optional<unsigned>{};
}

}  // namespace pyobfuscator::native::cff
