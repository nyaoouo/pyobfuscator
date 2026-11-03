#include "import_routes.hpp"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_import_sites(llvm::Function &function, const ResolvedRecipe &recipe) {
    return discover_function_references(function, recipe, true);
}

unsigned normalize_import_routes(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    return normalize_reference_component(function, recipe, coverage, true);
}

unsigned bind_import_routes(llvm::BasicBlock &body, llvm::Value *state_slot,
    std::uint32_t expected, std::uint32_t, SiteCoverage *coverage) {
    return bind_reference_component(body, state_slot, expected, coverage, true);
}

}  // namespace pyobfuscator::native::cff
