#include "site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {

std::set<std::string> duplicated_provenance(const llvm::Function &function) {
    std::set<std::string> seen, duplicates;
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto id = instruction_provenance(instruction);
        if (!id.empty() && !seen.insert(id).second) duplicates.insert(id);
    }
    return duplicates;
}

std::string instruction_provenance(const llvm::Instruction &instruction) {
    const auto *node = instruction.getMetadata("pyobf.cff.site");
    const auto *value = node != nullptr && node->getNumOperands() == 1 ? llvm::dyn_cast<llvm::MDString>(node->getOperand(0)) : nullptr;
    return value == nullptr ? std::string{} : value->getString().str();
}

}  // namespace pyobfuscator::native::cff
