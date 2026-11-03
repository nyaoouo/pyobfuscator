#include "reference_routes.hpp"
#include "source_marker.hpp"

#include <set>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {
namespace {

const llvm::Function *nested_function(const llvm::Value *value, bool imported, unsigned depth = 0) {
    if (const auto *function = llvm::dyn_cast<llvm::Function>(value))
        return function->isDeclaration() == imported ? function : nullptr;
    const auto *constant = llvm::dyn_cast<llvm::Constant>(value);
    if (depth > 32 || constant == nullptr || llvm::isa<llvm::GlobalValue>(constant)) return nullptr;
    for (const auto &operand : constant->operands())
        if (const auto *function = nested_function(operand, imported, depth + 1)) return function;
    return nullptr;
}

}  // namespace

const llvm::Function *reference_function(const llvm::Value *value) {
    if (!value->getType()->isPointerTy() || value->getType()->getPointerAddressSpace() != 0) return nullptr;
    return llvm::dyn_cast<llvm::Function>(value->stripPointerCasts());
}

std::string reference_reason(const llvm::Instruction &instruction, unsigned operand) {
    const auto *target = reference_function(instruction.getOperand(operand));
    if (target == nullptr) return "reference routes require a scalar AS0 function pointer operand";
    if (target->getAddressSpace() != 0) return "reference routes require AS0 function definitions";
    if (target->hasAvailableExternallyLinkage()) return "reference routes require emitted function definitions";
    if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
        if ((!llvm::isa<llvm::CallInst>(call) && !llvm::isa<llvm::InvokeInst>(call)) ||
            call->isMustTailCall() || call->hasOperandBundles() || call->isInlineAsm())
            return "reference routes do not support musttail, bundles, callbr or assembly operands";
        if (call->getCalledFunction() != nullptr && call->getCalledFunction()->isIntrinsic())
            return "reference routes retain intrinsic/control operands";
        if (call->isCallee(&instruction.getOperandUse(operand)) &&
            (call->getFunctionType()->isVarArg() || call->getFunctionType() != target->getFunctionType() ||
             call->getCallingConv() != target->getCallingConv()))
            return "reference routes require an exact nonvariadic call ABI";
    }
    if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction); store != nullptr && operand != 0)
        return "reference routes do not rewrite function addresses used as writable storage";
    if (!llvm::isa<llvm::CallInst>(instruction) && !llvm::isa<llvm::InvokeInst>(instruction) &&
        !llvm::isa<llvm::ReturnInst>(instruction) &&
        !llvm::isa<llvm::StoreInst>(instruction) && !llvm::isa<llvm::SelectInst>(instruction) &&
        !llvm::isa<llvm::ICmpInst>(instruction) && !llvm::isa<llvm::PHINode>(instruction) &&
        !llvm::isa<llvm::PtrToIntInst>(instruction))
        return "reference routes do not support this function-address operation";
    return {};
}

std::vector<InstructionSite> discover_function_references(llvm::Function &function, const ResolvedRecipe &recipe, bool imported) {
    std::vector<InstructionSite> sites;
    std::set<const llvm::Function *> targets;
    const auto &layout = function.getParent()->getDataLayout();
    const bool known_layout = !function.getParent()->getDataLayoutStr().empty() &&
        (layout.getPointerSizeInBits() == 32 || layout.getPointerSizeInBits() == 64);
    for (auto &block : function) for (auto &instruction : block) {
        for (unsigned index = 0; index < instruction.getNumOperands(); ++index) {
            const auto *nested = nested_function(instruction.getOperand(index), imported);
            if (nested == nullptr || nested->isDeclaration() != imported || nested->isIntrinsic() ||
                    source_marker_name(nested->getName())) continue;
            auto reason = known_layout ? reference_reason(instruction, index) :
                "reference routes need an explicit 32-bit or 64-bit target layout";
            if (imported && !nested->hasExternalLinkage()) reason = "import routes require strong external declarations";
            if (imported && (layout.getAllocaAddrSpace() != 0 || function.hasFnAttribute(llvm::Attribute::Naked)))
                reason = "import routes require an ordinary AS0 stack";
            if (imported) if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
                if (call->isConvergent() || call->cannotDuplicate() || call->cannotMerge() ||
                    call->hasFnAttr(llvm::Attribute::ReturnsTwice)) reason = "import routes retain special call-control semantics";
                for (unsigned argument = 0; argument < call->arg_size(); ++argument)
                    for (const auto kind : {llvm::Attribute::InAlloca, llvm::Attribute::Preallocated,
                                           llvm::Attribute::SwiftError, llvm::Attribute::SwiftSelf, llvm::Attribute::Nest})
                        if (call->paramHasAttr(argument, kind)) reason = "import routes retain special parameter ABI";
            }
            if (reason.empty()) targets.insert(reference_function(instruction.getOperand(index)));
            sites.push_back({&instruction, index, std::move(reason)});
        }
    }
    if (targets.size() >= (imported ? recipe.max_import_slots : recipe.max_reference_slots))
        for (auto &site : sites) if (site.reason.empty()) site.reason = imported ?
            "import targets exceed max_import_slots with a null slot" : "reference targets exceed max_reference_slots with a null slot";
    if (sites.size() > (imported ? recipe.max_import_sites : recipe.max_reference_sites))
        for (auto &site : sites) if (site.reason.empty()) site.reason = imported ?
            "import uses exceed max_import_sites" : "reference uses exceed max_reference_sites";
    return sites;
}

std::vector<InstructionSite> discover_reference_sites(llvm::Function &function, const ResolvedRecipe &recipe) {
    return discover_function_references(function, recipe, false);
}

}  // namespace pyobfuscator::native::cff
