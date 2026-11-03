#include "contribution_gate.hpp"
#include "contribution_query.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
void reject_contribution_artifacts(const llvm::Module &module) {
    for (const auto &function : module) {
        if (function.hasFnAttribute("pyobf.contribution.bound") || function.hasFnAttribute("pyobf.contribution.count") ||
                function.hasFnAttribute("pyobf.contribution.grouped") || function.hasFnAttribute("pyobf.contribution.queries") ||
                function.hasFnAttribute("pyobf.contribution.scope"))
            llvm::report_fatal_error("contribution input already contains generated binding artifacts");
        for (const auto &body : function) for (const auto &instruction : body) {
            for (const auto *tag : {"pyobf.contribution.root", "pyobf.contribution.query",
                    "pyobf.contribution.site", "pyobf.contribution.transition", "pyobf.contribution.source"})
                if (instruction.getMetadata(tag))
                    llvm::report_fatal_error("contribution input already contains generated binding artifacts");
            const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
            const auto *target = call == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCasts());
            if (target != nullptr && reserved_contribution_query(target->getName()))
                llvm::report_fatal_error("contribution input contains a reserved generated query call");
        }
    }
}
}
