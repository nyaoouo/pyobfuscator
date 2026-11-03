#include "cff.hpp"

#include <map>
#include <string>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

std::map<std::string, std::string> collect_marked_functions(const llvm::Module &module) {
    std::map<std::string, std::string> marked;
    const auto *global = module.getGlobalVariable("llvm.global.annotations");
    if (global == nullptr || !global->hasInitializer()) {
        return marked;
    }
    const auto *entries = llvm::dyn_cast<llvm::ConstantArray>(global->getInitializer());
    if (entries == nullptr) {
        llvm::report_fatal_error("native CFF cannot parse llvm.global.annotations");
    }
    for (unsigned index = 0; index < entries->getNumOperands(); ++index) {
        const auto *row = llvm::dyn_cast<llvm::Constant>(entries->getOperand(index));
        if (row == nullptr) {
            continue;
        }
        const auto *label_value = row->getAggregateElement(1u);
        const auto *label_global = label_value == nullptr ? nullptr :
            llvm::dyn_cast<llvm::GlobalVariable>(label_value->stripPointerCasts());
        const auto *label_data = label_global == nullptr || !label_global->hasInitializer() ?
            nullptr : llvm::dyn_cast<llvm::ConstantDataSequential>(label_global->getInitializer());
        if (label_data == nullptr || !label_data->isCString()) {
            continue;
        }
        const auto label = label_data->getAsCString();
        if (label != "pyobf.native.cff" && label != "pyobf.native.sdk" &&
            label != "pyobf.native.bootstrap" && label != "pyobf.native.bootstrap.eh") {
            continue;
        }
        const auto *function_value = row->getAggregateElement(0u);
        const auto *function = function_value == nullptr ? nullptr :
            llvm::dyn_cast<llvm::Function>(function_value->stripPointerCastsAndAliases());
        if (function == nullptr) {
            llvm::report_fatal_error("native CFF marker does not reference a function");
        }
        const auto [it, inserted] = marked.emplace(function->getName().str(), label.str());
        if (!inserted && it->second != label) {
            llvm::report_fatal_error("native CFF function has conflicting source markers");
        }
    }
    return marked;
}

}  // namespace pyobfuscator::native::cff
