#include "path_fold_sites.hpp"
#include "path_fold_marker.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

FoldMarker inspect_path_fold_marker(llvm::Instruction &instruction) {
    auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
    auto *target = call == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCasts());
    if (target == nullptr || !path_fold_marker_name(target->getName())) return {};
    FoldMarker result;
    result.call = llvm::dyn_cast<llvm::CallInst>(call);
    result.kind = target->getName().ends_with("init_v1") ? FoldKind::initialize : FoldKind::advance;
    const unsigned arguments = result.kind == FoldKind::initialize ? 2 : 3;
    if (result.call == nullptr || call->getCalledFunction() != target || !target->isDeclaration() ||
            target->hasDLLImportStorageClass() || !target->hasExternalLinkage() || target->getAddressSpace() != 0 ||
            target->isVarArg() || call->getFunctionType() != target->getFunctionType() ||
            !call->getType()->isVoidTy() || call->arg_size() != arguments ||
            target->getCallingConv() != llvm::CallingConv::C || call->getCallingConv() != llvm::CallingConv::C || !call->doesNotThrow() ||
            call->hasOperandBundles() || result.call->isMustTailCall() || call->isConvergent() ||
            call->hasFnAttr(llvm::Attribute::ReturnsTwice)) {
        result.reason = "path-fold needs a direct nounwind C marker declaration with its exact v1 ABI";
        return result;
    }
    if (instruction.getParent()->isEHPad()) {
        result.reason = "path-fold supports normal CFF body sites, not EH pad headers";
        return result;
    }
    for (const auto &use : target->uses()) {
        const auto *direct = llvm::dyn_cast<llvm::CallInst>(use.getUser());
        if (direct == nullptr || !direct->isCallee(&use)) {
            result.reason = "path-fold marker address escapes its closed direct-call uses";
            return result;
        }
    }
    for (unsigned index = 0; index != arguments; ++index)
        for (const auto kind : {llvm::Attribute::ByVal, llvm::Attribute::ByRef, llvm::Attribute::StructRet,
                               llvm::Attribute::InAlloca, llvm::Attribute::Preallocated,
                               llvm::Attribute::SwiftError, llvm::Attribute::SwiftSelf, llvm::Attribute::Nest})
            if (call->paramHasAttr(index, kind) || target->hasParamAttribute(index, kind)) {
                result.reason = "path-fold marker parameters cannot change the ordinary v1 reference ABI";
                return result;
            }
    auto *storage = call->getArgOperand(0);
    if (!storage->getType()->isPointerTy() || storage->getType()->getPointerAddressSpace() != 0 ||
            llvm::isa<llvm::ConstantPointerNull>(storage) || llvm::isa<llvm::UndefValue>(storage) ||
            llvm::isa<llvm::PoisonValue>(storage) || call->getParamDereferenceableBytes(0) < 32 ||
            call->getParamAlign(0).valueOrOne() < llvm::Align(4)) {
        result.reason = "path-fold needs a live aligned eight-word storage reference";
        return result;
    }
    for (unsigned index = 1; index != arguments; ++index) {
        const auto *word = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(index));
        if (word == nullptr || !word->getType()->isIntegerTy(32)) {
            result.reason = "path-fold v1 seed, tag and normal word must be fixed i32 values";
            return result;
        }
        if (index == arguments - 1) result.word = static_cast<std::uint32_t>(word->getZExtValue());
        else result.tag = static_cast<std::uint32_t>(word->getZExtValue());
    }
    return result;
}

std::vector<InstructionSite> discover_path_fold_sites(llvm::Function &function, const ResolvedRecipe &recipe) {
    std::vector<InstructionSite> result;
    for (auto &block : function) for (auto &instruction : block) {
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        const auto *target = call == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCasts());
        if (target != nullptr && path_fold_marker_name(target->getName()))
            result.push_back({&instruction, 0, inspect_path_fold_marker(instruction).reason});
    }
    if (result.size() > recipe.max_path_fold_sites)
        for (auto &site : result) site.reason = "path-fold sites exceed max_path_fold_sites";
    return result;
}

}  // namespace pyobfuscator::native::cff
