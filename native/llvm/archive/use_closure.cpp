#include "plan.hpp"
#include "control_operands.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::archive {

std::string closed_global_uses(llvm::GlobalVariable &global,
                                 const std::set<std::string> &functions,
                                 std::vector<UseSite> &uses) {
    if (!global.hasLocalLinkage() || !global.isConstant() || !global.hasInitializer())
        return "archive global requires local immutable defined storage";
    if (global.isThreadLocal() || global.hasSection() || global.hasComdat() ||
        global.isExternallyInitialized() || global.getAddressSpace() != 0)
        return "archive global has unsupported TLS, section, COMDAT, initialization or address space";
    llvm::SmallVector<llvm::Value *, 16> pending{&global};
    llvm::SmallPtrSet<llvm::Value *, 32> visited;
    while (!pending.empty()) {
        auto *value = pending.pop_back_val();
        if (!visited.insert(value).second) continue;
        if (visited.size() > 1048576) return "archive address-use closure exceeds its budget";
        for (auto &use : value->uses()) {
            auto *user = use.getUser();
            if (auto *instruction = llvm::dyn_cast<llvm::Instruction>(user)) {
                if (llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) continue;
                if (control_operand(*instruction, use.getOperandNo()))
                    return "archive global has an exception ABI/control use";
                if (!functions.count(instruction->getFunction()->getName().str()))
                    return "archive global has a use outside selected functions";
                uses.push_back({instruction, use.getOperandNo()});
            } else if (llvm::isa<llvm::ConstantExpr>(user) ||
                       llvm::isa<llvm::ConstantAggregate>(user)) {
                pending.push_back(user);
            } else {
                return "archive address escapes through a global initializer, alias or unknown user";
            }
        }
    }
    if (uses.empty()) return "archive global has no selected executable use";
    return {};
}

std::set<std::string> early_functions(const llvm::Module &module) {
    std::set<std::string> result;
    llvm::SmallVector<const llvm::Function *, 16> pending;
    for (const auto name : {"llvm.global_ctors", "llvm.global_dtors"}) {
        const auto *global = module.getNamedGlobal(name);
        if (global == nullptr || !global->hasInitializer()) continue;
        const auto *array = llvm::dyn_cast<llvm::ConstantArray>(global->getInitializer());
        if (array == nullptr) continue;
        for (const auto &element : array->operands()) {
            const auto *record = llvm::dyn_cast<llvm::ConstantStruct>(element.get());
            if (record != nullptr && record->getNumOperands() >= 2)
                if (const auto *function = llvm::dyn_cast<llvm::Function>(
                        record->getOperand(1)->stripPointerCastsAndAliases())) pending.push_back(function);
        }
    }
    // Known Windows loader-lock roots; this is not proof about opaque external callbacks.
    for (const auto &function : module)
        if (function.getName() == "DllMain" || function.getName() == "_DllMain@12" ||
            function.getName() == "DllMainCRTStartup" || function.getName() == "_DllMainCRTStartup@12")
            pending.push_back(&function);
    while (!pending.empty()) {
        const auto *function = pending.pop_back_val();
        if (!result.insert(function->getName().str()).second) continue;
        for (const auto &block : *function) for (const auto &instruction : block)
            if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
                if (const auto *callee = llvm::dyn_cast<llvm::Function>(
                        call->getCalledOperand()->stripPointerCastsAndAliases())) pending.push_back(callee);
    }
    return result;
}

}  // namespace pyobfuscator::native::archive
