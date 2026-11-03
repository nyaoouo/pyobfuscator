#include "site_provenance.hpp"

#include "recipe.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {

std::string instruction_site_id(const llvm::Instruction &instruction,
                                  llvm::StringRef component, unsigned operand) {
    if (const auto *descriptor = find_component(component);
        descriptor != nullptr && descriptor->identity_operand != nullptr)
        operand = descriptor->identity_operand(instruction, operand);
    return instruction_provenance(instruction) + ":" + component.str() + ":" + std::to_string(operand);
}

void ensure_generated_provenance(llvm::Instruction &instruction, unsigned &sequence) {
    if (!instruction_provenance(instruction).empty()) return;
    const auto id = "generated." + std::to_string(component_seed(
        0, instruction.getFunction()->getName(), "site")) + "." + std::to_string(sequence++);
    instruction.setMetadata("pyobf.cff.site", llvm::MDNode::get(instruction.getContext(),
        llvm::MDString::get(instruction.getContext(), id)));
}

}  // namespace pyobfuscator::native::cff
