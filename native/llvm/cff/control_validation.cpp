#include "control_validation.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::string validate_control_semantics(const llvm::Function &function) {
    if (function.hasFnAttribute(llvm::Attribute::ReturnsTwice))
        return "native CFF does not support returns-twice nonlocal control";
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (call == nullptr) continue;
        const auto *target = llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCastsAndAliases());
        if (call->hasFnAttr(llvm::Attribute::ReturnsTwice) ||
            (target != nullptr && target->hasFnAttribute(llvm::Attribute::ReturnsTwice)))
            return "native CFF does not support returns-twice nonlocal control";
        if (target != nullptr && target->getName().starts_with("llvm.eh.sjlj."))
            return "native CFF does not support SJLJ nonlocal control";
        if (target != nullptr && target->getName().starts_with("llvm.coro."))
            return "native CFF does not support coroutine intrinsics";
    }
    return {};
}

}  // namespace pyobfuscator::native::cff
