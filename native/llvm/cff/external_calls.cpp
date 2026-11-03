#include "external_calls.hpp"
#include "call_frames.hpp"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_external_calls(llvm::Function &function, const ResolvedRecipe &recipe) {
    return discover_frame_calls(function, recipe, true);
}

void plan_external_calls(llvm::Module &module, const std::map<std::string, ResolvedRecipe> &recipes,
                           std::vector<GeneratedDefinition> &generated) {
    plan_frame_component(module, recipes, generated, "external-calls");
}

unsigned normalize_external_calls(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    return normalize_frame_component(function, recipe, coverage, "external-calls");
}

}  // namespace pyobfuscator::native::cff
