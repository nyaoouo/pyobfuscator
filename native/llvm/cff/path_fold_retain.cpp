#include "path_fold_sites.hpp"
#include "path_fold_marker.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
void retain_path_fold_markers(llvm::Function &function, const ResolvedRecipe &) {
    for (auto &body : function) for (auto &instruction : body)
        if (auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction))
            if (const auto *target = call->getCalledFunction();
                target != nullptr && path_fold_marker_name(target->getName())) {
                call->addFnAttr(llvm::Attribute::NoMerge);
                call->addFnAttr(llvm::Attribute::NoDuplicate);
            }
}
}
