#include "hybrid_eh.hpp"

#include "cff.hpp"
#include "recipe.hpp"

#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

std::string validate_hybrid_eh(const llvm::Function &function) {
    if (const auto reason = validate_cfg_shape(function, true); !reason.empty()) return reason;
    if (function.getParent()->getTargetTriple().str() != "x86_64-w64-windows-gnu")
        return "hybrid-eh target model is not verified; requires x64 Windows GNU";
    const auto *personality = function.hasPersonalityFn() ? llvm::dyn_cast<llvm::Function>(
        function.getPersonalityFn()->stripPointerCastsAndAliases()) : nullptr;
    if (personality == nullptr || personality->getName() != "__gxx_personality_seh0")
        return "hybrid-eh requires the Windows GNU C++ landingpad personality";
    bool has_invoke = false;
    for (const auto &block : function) {
        if (block.isEHPad() && !llvm::isa<llvm::LandingPadInst>(&*block.getFirstNonPHIIt()))
            return "hybrid-eh does not support funclet pads";
        for (const auto &instruction : block) {
            if (instruction.getType()->isTokenTy()) return "hybrid-eh does not support token values";
            if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
                if (call->hasOperandBundles()) return "hybrid-eh does not support operand bundles";
        }
        if (const auto *invoke = llvm::dyn_cast<llvm::InvokeInst>(block.getTerminator())) {
            has_invoke = true;
            if (!invoke->getUnwindDest()->isLandingPad())
                return "hybrid-eh requires landingpad unwind destinations";
        }
    }
    return has_invoke ? "" : "hybrid-eh requires an invoke boundary";
}

std::string validate_configured(const llvm::Function &function, const ResolvedRecipe &recipe) {
    return recipe.coverage == "hybrid-eh" ? validate_hybrid_eh(function) : validate_relative_tree(function);
}

}  // namespace pyobfuscator::native::cff
