#pragma once

#include <string>
#include <set>

#include "llvm/ADT/StringRef.h"

namespace llvm {
class Instruction;
class Function;
}

namespace pyobfuscator::native::cff {

std::string instruction_provenance(const llvm::Instruction &instruction);
std::string instruction_site_id(const llvm::Instruction &instruction,
                                  llvm::StringRef component, unsigned operand);
void ensure_generated_provenance(llvm::Instruction &instruction, unsigned &sequence);
std::set<std::string> duplicated_provenance(const llvm::Function &function);

}  // namespace pyobfuscator::native::cff
