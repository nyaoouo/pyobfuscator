#pragma once

#include <string>
#include <vector>

#include "../cff/recipe.hpp"
#include "../cff/site_report.hpp"

namespace llvm { class Module; }

namespace pyobfuscator::native::archive {

struct SourceReport {
    llvm::json::Object report;
    llvm::json::Array private_map;
    std::string failure;
};

std::vector<cff::InstructionSite> source_candidates(llvm::Function &function, bool integers);
SourceReport inspect_sources(llvm::Function &function, const std::vector<cff::RequestedSite> &requests,
                                bool bound, bool strict_requests = false);
void preflight_prepared(llvm::Module &module, const std::map<std::string, cff::ResolvedRecipe> &recipes);
void finish_bindings(llvm::Module &module);

}  // namespace pyobfuscator::native::archive
