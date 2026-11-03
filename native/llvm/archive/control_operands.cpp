#include "control_operands.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"

namespace pyobfuscator::native::archive {

bool control_operand(const llvm::Instruction &instruction, unsigned operand) {
    if (instruction.isEHPad() || llvm::isa<llvm::ResumeInst>(instruction)) return true;
    const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
    const auto *target = call == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(
        call->getCalledOperand()->stripPointerCastsAndAliases());
    if (target == nullptr) return false;
    if (target->getIntrinsicID() == llvm::Intrinsic::eh_typeid_for) return true;
    // GNU exception-runtime type_info operands carry ABI identity, not archived
    // object contents. Ordinary data sharing this address still fails closure.
    return operand == 1 && target->isDeclaration() && call->arg_size() == 3 &&
        call->getArgOperand(1)->getType()->isPointerTy() &&
        (target->getName() == "__cxa_throw" || target->getName() == "__cxa_init_primary_exception");
}

}  // namespace pyobfuscator::native::archive
