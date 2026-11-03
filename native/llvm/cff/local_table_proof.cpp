#include "indexed_locals.hpp"
#include "call_frames.hpp"
#include "scalar_proof.hpp"

#include <algorithm>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

std::optional<std::vector<const llvm::AllocaInst *>> local_table_targets(const llvm::AllocaInst *table) {
    const auto *array = table == nullptr ? nullptr : llvm::dyn_cast<llvm::ArrayType>(table->getAllocatedType());
    const auto *count = table == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(table->getArraySize());
    const auto *tag = table == nullptr ? nullptr : table->getMetadata("pyobf.local.table");
    if (array == nullptr || !array->getElementType()->isPointerTy() || array->getElementType()->getPointerAddressSpace() != 0 ||
        table->getAddressSpace() != 0 || count == nullptr || !count->isOne() ||
        table->getParent() != &table->getFunction()->getEntryBlock() || array->getNumElements() < 2 || array->getNumElements() > 4096 ||
        (array->getNumElements() & (array->getNumElements() - 1)) || tag == nullptr || tag->getNumOperands() != 1 ||
        frame_number(tag, 0) != array->getNumElements()) return {};
    const auto alignment = table->getModule()->getDataLayout().getABITypeAlign(array->getElementType());
    if (table->getAlign() != alignment) return {};
    std::vector<const llvm::AllocaInst *> targets(array->getNumElements(), nullptr);
    std::set<unsigned> initialized;
    for (const auto *user : table->users()) {
        const auto *address = llvm::dyn_cast<llvm::GetElementPtrInst>(user);
        if (address == nullptr || address->getPointerOperand() != table || address->getSourceElementType() != array ||
            address->getFunction() != table->getFunction() || address->getNumIndices() != 2 || !scalar_constant(address->getOperand(1), 0)) return {};
        const auto *initializer = address->getMetadata("pyobf.local.initializer");
        if (initializer == nullptr) {
            if (address->getMetadata("pyobf.local.bound") == nullptr) return {};
            continue;
        }
        const auto *index = llvm::dyn_cast<llvm::ConstantInt>(address->getOperand(2));
        const auto *store = address->hasOneUse() ? llvm::dyn_cast<llvm::StoreInst>(*address->user_begin()) : nullptr;
        const auto *store_tag = store == nullptr ? nullptr : store->getMetadata("pyobf.local.initializer");
        if (initializer->getNumOperands() != 0 || index == nullptr || !index->getType()->isIntegerTy(32) ||
            index->getValue().uge(targets.size()) || store == nullptr || !store->isVolatile() || store->isAtomic() ||
            store->getPointerOperand() != address || store->getParent() != &table->getFunction()->getEntryBlock() ||
            address->getParent() != store->getParent() || store->getAlign() != alignment ||
            store_tag == nullptr || store_tag->getNumOperands() != 0 || !initialized.insert(index->getZExtValue()).second) return {};
        if (llvm::isa<llvm::ConstantPointerNull>(store->getValueOperand())) continue;
        const auto *object = llvm::dyn_cast<llvm::AllocaInst>(store->getValueOperand());
        const auto info = object == nullptr ? std::optional<LocalInfo>{} : local_info(object->getMetadata("pyobf.local.object"));
        const auto *object_count = object == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(object->getArraySize());
        if (!info || object == table || !object->isStaticAlloca() || compiler_local_storage(*object) ||
            object->getAddressSpace() != 0 || object->getFunction() != table->getFunction() ||
            info->slot != index->getZExtValue() || info->type != object->getAllocatedType() ||
            info->alignment != object->getAlign().value() || object_count == nullptr || object_count->getValue().getActiveBits() > 63 ||
            object_count->getZExtValue() != info->count || object->isUsedWithInAlloca() || object->isSwiftError()) return {};
        targets[index->getZExtValue()] = object;
    }
    if (initialized.size() != targets.size() || std::find(targets.begin(), targets.end(), nullptr) == targets.end()) return {};
    return targets;
}

}  // namespace pyobfuscator::native::cff
