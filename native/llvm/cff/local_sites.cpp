#include "indexed_locals.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

bool local_control_use(const llvm::Instruction &instruction) {
    if (llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) return true;
    const auto *call = llvm::dyn_cast<llvm::IntrinsicInst>(&instruction);
    return call != nullptr && (call->getIntrinsicID() == llvm::Intrinsic::lifetime_start ||
        call->getIntrinsicID() == llvm::Intrinsic::lifetime_end);
}

bool compiler_local_storage(const llvm::AllocaInst &storage) {
    if (storage.getMetadata("pyobf.frame.storage") || storage.getMetadata("pyobf.ref.table") || storage.getMetadata("pyobf.local.table")) return true;
    for (const auto *user : storage.users())
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(user); call != nullptr &&
            call->getMetadata("pyobf.archive.gate") && call->arg_size() && call->getArgOperand(0) == &storage) return true;
    return false;
}

std::vector<LocalObject> collect_local_objects(llvm::Function &function, const ResolvedRecipe &recipe) {
    std::vector<LocalObject> objects;
    if (function.hasFnAttribute("pyobf.archive.wrapper")) return objects;
    const auto &data = function.getParent()->getDataLayout();
    const bool known = !function.getParent()->getDataLayoutStr().empty() &&
        (data.getPointerSizeInBits() == 32 || data.getPointerSizeInBits() == 64) && data.getAllocaAddrSpace() == 0;
    std::uint64_t routes = 0;
    unsigned eligible = 0;
    for (auto &block : function) for (auto &instruction : block) {
        auto *allocation = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
        if (allocation == nullptr || compiler_local_storage(*allocation)) continue;
        LocalObject object{allocation, {}, 0, {}};
        const auto *count = llvm::dyn_cast<llvm::ConstantInt>(allocation->getArraySize());
        auto *type = allocation->getAllocatedType();
        if (!known || allocation->getAddressSpace() != 0 || function.hasFnAttribute(llvm::Attribute::Naked))
            object.reason = "indexed locals need an explicit 32/64-bit AS0 stack layout";
        else if (!allocation->isStaticAlloca() || count == nullptr || count->isZero() || count->getValue().getActiveBits() > 63 ||
                 allocation->isUsedWithInAlloca() || allocation->isSwiftError())
            object.reason = "indexed locals retain dynamic, nonentry and special allocation ABI";
        else if (!type->isSized() || !type->isFirstClassType() || type->isTokenTy() || type->isScalableTy() ||
                 type->isTargetExtTy() || type->containsNonLocalTargetExtType() || data.getTypeAllocSize(type).isScalable() ||
                 data.getTypeAllocSize(type).getFixedValue() == 0)
            object.reason = "indexed local object has unsupported or empty storage";
        for (auto &use : allocation->uses()) {
            auto *consumer = llvm::dyn_cast<llvm::Instruction>(use.getUser());
            if (consumer == nullptr) { object.reason = "indexed local address has a non-instruction use"; continue; }
            if (local_control_use(*consumer)) { ++object.control_uses; continue; }
            if (const auto *call = llvm::dyn_cast<llvm::CallBase>(consumer)) {
                if ((call->getCalledFunction() != nullptr && call->getCalledFunction()->isIntrinsic() && !llvm::isa<llvm::MemIntrinsic>(call)) ||
                    call->hasOperandBundles() || call->isInlineAsm() || (llvm::isa<llvm::CallInst>(call) && llvm::cast<llvm::CallInst>(call)->isMustTailCall()))
                    object.reason = "indexed locals retain intrinsic, bundle, assembly and musttail control operands";
            }
            object.uses.push_back({consumer, use.getOperandNo()});
        }
        if (object.reason.empty() && object.uses.empty()) object.reason = "indexed locals require a non-control address use";
        if (object.reason.empty()) { ++eligible; routes += object.uses.size(); }
        objects.push_back(std::move(object));
    }
    unsigned slots = 2;
    while (slots <= eligible && slots <= 4096) slots *= 2;
    for (auto &object : objects) if (object.reason.empty()) {
        if (slots > recipe.max_local_slots) object.reason = "indexed locals exceed max_local_slots with a null slot";
        else if (routes > recipe.max_local_routes) object.reason = "indexed locals exceed max_local_routes";
        else if (static_cast<std::uint64_t>(slots) * data.getPointerSize() > recipe.max_local_bytes)
            object.reason = "indexed local table exceeds max_local_bytes";
    }
    return objects;
}

std::vector<InstructionSite> discover_indexed_locals(llvm::Function &function, const ResolvedRecipe &recipe) {
    std::vector<InstructionSite> sites;
    for (const auto &object : collect_local_objects(function, recipe)) sites.push_back({object.storage, 0, object.reason});
    return sites;
}

}  // namespace pyobfuscator::native::cff
