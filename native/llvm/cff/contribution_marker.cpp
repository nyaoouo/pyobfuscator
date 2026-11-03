#include "contribution_gate.hpp"
#include "contribution_private.hpp"
#include "contribution_query.hpp"
#include "contribution_reference_origin.hpp"
#include "region_scope.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
std::string inspect(llvm::CallBase &call, bool mixed) {
    const auto *target = call.getCalledFunction();
    const auto count = mixed ? 3u : 2u;
    const auto site_index = mixed ? 2u : 1u;
    if (!llvm::isa<llvm::CallInst>(call) || target == nullptr || !target->isDeclaration() ||
            target->hasDLLImportStorageClass() || !target->hasExternalLinkage() ||
            target->isVarArg() || target->getCallingConv() != llvm::CallingConv::C ||
            call.getCallingConv() != llvm::CallingConv::C || !call.getType()->isVoidTy() ||
            call.arg_size() != count || target->arg_size() != count || !call.doesNotThrow() || call.hasOperandBundles() ||
            call.isConvergent() || call.hasFnAttr(llvm::Attribute::ReturnsTwice) ||
            llvm::cast<llvm::CallInst>(call).isMustTailCall())
        return "contribution needs an exact direct nounwind C source marker declaration";
    const auto *lease = call.getArgOperand(0);
    const auto *site = llvm::dyn_cast<llvm::ConstantInt>(call.getArgOperand(site_index));
    if (!lease->getType()->isPointerTy() || lease->getType()->getPointerAddressSpace() != 0 ||
            llvm::isa<llvm::ConstantPointerNull>(lease) || llvm::isa<llvm::UndefValue>(lease) ||
            llvm::isa<llvm::PoisonValue>(lease) || site == nullptr || !site->getType()->isIntegerTy(32) || site->isZero())
        return "contribution needs a live lease reference and nonzero fixed i32 site identity";
    if (mixed) {
        const auto *scope = call.getArgOperand(1);
        if (!scope->getType()->isPointerTy() || scope->getType()->getPointerAddressSpace() != 0 ||
                scope == lease || llvm::isa<llvm::ConstantPointerNull, llvm::UndefValue, llvm::PoisonValue>(scope) ||
                !target->getFunctionType()->getParamType(0)->isPointerTy() ||
                !target->getFunctionType()->getParamType(1)->isPointerTy() ||
                !target->getFunctionType()->getParamType(2)->isIntegerTy(32))
            return "mixed contribution needs distinct live owned and measured references with exact ABI";
        const auto owned_origin = contribution_reference_argument(call.getArgOperand(0), *call.getFunction());
        const auto measured_origin = contribution_reference_argument(call.getArgOperand(1), *call.getFunction());
        if (!owned_origin || !measured_origin || owned_origin == measured_origin)
            return "mixed contribution references need distinct canonical function arguments";
    }
    for (const auto kind : {llvm::Attribute::ByVal, llvm::Attribute::ByRef, llvm::Attribute::StructRet,
            llvm::Attribute::InAlloca, llvm::Attribute::Preallocated, llvm::Attribute::SwiftError,
            llvm::Attribute::SwiftSelf, llvm::Attribute::Nest})
        if (call.paramHasAttr(0, kind) || target->hasParamAttribute(0, kind) ||
                (mixed && (call.paramHasAttr(1, kind) || target->hasParamAttribute(1, kind))))
            return "contribution marker cannot alter the ordinary reference ABI";
    for (const auto &use : target->uses()) {
        const auto *direct = llvm::dyn_cast<llvm::CallInst>(use.getUser());
        if (direct == nullptr || !direct->isCallee(&use)) return "contribution marker address escapes";
    }
    if (call.getParent()->isEHPad()) return "explicit contribution point cannot use an EH pad header";
    return {};
}
}
std::vector<InstructionSite> discover_contribution_sites(llvm::Function &function, const ResolvedRecipe &recipe) {
    std::vector<InstructionSite> result;
    for (auto &body : function) for (auto &instruction : body) {
        if (recipe.region_scope && !recipe.region_scope->contains(body)) continue;
        auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        const auto *target = call == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCasts());
        if (target == nullptr || (target->getName() != "pyobf_native_contribution_site_v1" &&
                target->getName() != "pyobf_native_measured_contribution_site_v1" &&
                target->getName() != "pyobf_native_mixed_contribution_site_v1")) continue;
        const bool mixed = target->getName() == "pyobf_native_mixed_contribution_site_v1";
        auto reason = inspect(*call, mixed);
        if (reason.empty() && mixed && (!recipe.contribution || recipe.contribution->schema != 4))
            reason = "mixed contribution marker requires schema4 source binding";
        if (reason.empty()) {
            auto expected = contribution_marker_name(recipe);
            if (recipe.contribution && recipe.contribution->schema >= 3) {
                const auto label = llvm::cast<llvm::ConstantInt>(call->getArgOperand(mixed ? 2 : 1))->getZExtValue();
                const auto *group = recipe.contribution->group(function.getName().str(), label);
                if (group == nullptr) reason = "mixed contribution marker has no explicit site rule";
                else if (recipe.contribution->schema == 4) expected = "pyobf_native_mixed_contribution_site_v1";
                else expected = group->binding.sources.front().spec.provider == "measured-scope-v1" ?
                    "pyobf_native_measured_contribution_site_v1" : "pyobf_native_contribution_site_v1";
            }
            if (reason.empty() && target->getName() != expected)
                reason = "contribution marker differs from its configured provider";
        }
        result.push_back({call, 0, reason});
    }
    if (result.size() > recipe.max_contribution_sites)
        for (auto &site : result) site.reason = "contribution sites exceed max_contribution_sites";
    return result;
}
}
