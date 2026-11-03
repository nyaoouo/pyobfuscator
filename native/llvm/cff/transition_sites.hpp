#pragma once

#include "recipe.hpp"
#include <functional>

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_transition_sites(llvm::Function &function, unsigned limit,
                                                       std::uint32_t seed);
std::vector<llvm::Instruction *> select_prepared_sites(SiteCoverage &coverage,
    llvm::StringRef component, unsigned limit,
    const std::function<std::string(const llvm::Instruction &)> &exclude = {});
void mark_transition(llvm::Instruction &instruction, llvm::StringRef marker);
bool transition_marked(const llvm::Instruction &instruction, llvm::StringRef marker);

}  // namespace pyobfuscator::native::cff
