#include "call_frames.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

namespace pyobfuscator::native::cff {

void retain_call_frame_abis(llvm::Function &function, const ResolvedRecipe &recipe) {
    if (recipe.requirement("call-frames") != Requirement::required &&
        recipe.requirement("call-preparation") != Requirement::required) return;

    auto &module = *function.getParent();
    llvm::SmallVector<llvm::GlobalValue *, 16> retained, added;
    llvm::collectUsedGlobalVariables(module, retained, true);
    std::set<llvm::GlobalValue *> known(retained.begin(), retained.end());
    for (const auto &site : discover_frame_calls(function, recipe, false)) {
        if (!site.reason.empty()) continue;
        auto *target = llvm::cast<llvm::CallBase>(site.instruction)->getCalledFunction();
        if (!target->hasLocalLinkage() || !known.insert(target).second) continue;
        added.push_back(target);
    }
    // Dead-argument/return elimination can recreate a live call without its source ID.
    // Preserve required local target ABIs without exporting them or rooting linker code.
    if (!added.empty()) llvm::appendToCompilerUsed(module, added);
}

}  // namespace pyobfuscator::native::cff
