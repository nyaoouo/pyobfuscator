#include "indexed_locals.hpp"
#include "call_frames.hpp"
#include "call_preparation.hpp"
#include "scalar_proof.hpp"
#include "ssa_origin.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

const llvm::AllocaInst *resolve_local_target(const llvm::Value *value) {
    value = unique_spill_origin(value);
    const auto *load = llvm::dyn_cast_or_null<llvm::LoadInst>(value);
    const auto *address = load == nullptr ? nullptr : llvm::dyn_cast<llvm::GetElementPtrInst>(load->getPointerOperand());
    const auto *tag = address == nullptr ? nullptr : address->getMetadata("pyobf.local.bound");
    const auto *descriptor = tag != nullptr && tag->getNumOperands() == 4 ? llvm::dyn_cast<llvm::MDNode>(tag->getOperand(0)) : nullptr;
    const auto info = local_info(descriptor);
    const auto route = frame_number(tag, 1), salt = frame_number(tag, 2), expected = frame_number(tag, 3);
    const auto *table = address == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(address->getPointerOperand());
    const auto *array = table == nullptr ? nullptr : llvm::dyn_cast<llvm::ArrayType>(table->getAllocatedType());
    const auto targets = local_table_targets(table);
    if (!info || !route || !salt || !expected || !targets || *route >= info->routes || load == nullptr ||
        !load->isVolatile() || load->isAtomic() || !load->getType()->isPointerTy() || load->getType()->getPointerAddressSpace() != 0 ||
        !address->hasOneUse() || load->use_empty() || load->getParent() != address->getParent() || table == nullptr ||
        array == nullptr || !array->getElementType()->isPointerTy() || array->getElementType()->getPointerAddressSpace() != 0 ||
        table->getAddressSpace() != 0 || address->getSourceElementType() != array || address->getNumIndices() != 2 ||
        array->getNumElements() < 2 || array->getNumElements() > 4096 || (array->getNumElements() & (array->getNumElements() - 1)) ||
        info->slot >= array->getNumElements() || load->getAlign() != table->getAlign() ||
        !scalar_constant(address->getOperand(1), 0)) return nullptr;
    const auto *bounded = scalar_operation(address->getOperand(2), llvm::Instruction::And, address->getParent());
    const auto *decoded = bounded == nullptr ? nullptr : scalar_operation(bounded->getOperand(0), llvm::Instruction::Xor, address->getParent());
    const auto encoded = info->slot ^ static_cast<std::uint32_t>(scalar_mask_value(32, *expected, *salt, ScalarMaskDomain::local).getZExtValue());
    if (bounded == nullptr || decoded == nullptr || !scalar_constant(bounded->getOperand(1), array->getNumElements() - 1) ||
        !scalar_constant(decoded->getOperand(1), encoded)) return nullptr;
    const auto *state_slot = match_scalar_mask(decoded->getOperand(0), *address->getParent(), *salt, *expected,
        ScalarMaskDomain::local, "pyobf.local.state", "pyobf.local.state-slot");
    if (state_slot == nullptr || !preparation_state_routes_to(*address->getParent(), state_slot, *expected)) return nullptr;
    const auto *object = (*targets)[info->slot];
    if (object == nullptr || object->getMetadata("pyobf.local.object") != descriptor) return nullptr;
    return object;
}

}  // namespace pyobfuscator::native::cff
