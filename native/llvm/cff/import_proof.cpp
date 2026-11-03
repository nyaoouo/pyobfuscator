#include "import_routes.hpp"
#include "call_preparation.hpp"
#include "scalar_proof.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

const llvm::Function *resolve_import_route(const llvm::LoadInst *load, const llvm::GetElementPtrInst *address,
    const llvm::AllocaInst *table, const ReferenceInfo &info) {
    const auto targets = reference_table_targets(table);
    const auto *array = table == nullptr ? nullptr : llvm::dyn_cast<llvm::ArrayType>(table->getAllocatedType());
    if (!info.imported || !targets || array == nullptr || info.slot >= targets->size() ||
        (*targets)[info.slot] != info.target || load == nullptr || !load->isVolatile() || load->isAtomic() ||
        !load->getType()->isPointerTy() || load->getType()->getPointerAddressSpace() != 0 || load->use_empty() ||
        !address->hasOneUse() || load->getParent() != address->getParent() || address->getSourceElementType() != array ||
        address->getNumIndices() != 2 || !scalar_constant(address->getOperand(1), 0) ||
        load->getAlign() != table->getAlign() || table->getAlign() <
            load->getModule()->getDataLayout().getABITypeAlign(load->getType())) return nullptr;
    const auto *bounded = scalar_operation(address->getOperand(2), llvm::Instruction::And, address->getParent());
    const auto *decoded = bounded == nullptr ? nullptr : scalar_operation(bounded->getOperand(0), llvm::Instruction::Xor, address->getParent());
    const auto encoded = info.slot ^ static_cast<std::uint32_t>(
        scalar_mask_value(32, info.state, info.salt, ScalarMaskDomain::import_route).getZExtValue());
    if (bounded == nullptr || decoded == nullptr || !scalar_constant(bounded->getOperand(1), targets->size() - 1) ||
        !scalar_constant(decoded->getOperand(1), encoded)) return nullptr;
    const auto *state_slot = match_scalar_mask(decoded->getOperand(0), *address->getParent(), info.salt, info.state,
        ScalarMaskDomain::import_route, "pyobf.ref.state", "pyobf.ref.state-slot");
    return state_slot != nullptr && preparation_state_routes_to(*address->getParent(), state_slot, info.state) ? info.target : nullptr;
}

}  // namespace pyobfuscator::native::cff
