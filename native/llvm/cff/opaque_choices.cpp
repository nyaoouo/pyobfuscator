#include "recipe.hpp"

#include "opaque_expression.hpp"
#include "site_provenance.hpp"
#include "site_report.hpp"
#include "transition_sites.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_opaque_sites(llvm::Function &function,
                                                  const ResolvedRecipe &recipe) {
    return discover_transition_sites(function, recipe.max_opaque_sites, recipe.seeds.at("opaque-choices"));
}

unsigned prepare_opaque_choices(llvm::Function &, llvm::Value *, const ResolvedRecipe &recipe,
                                 SiteCoverage &coverage) {
    const auto selected = select_prepared_sites(coverage, "opaque-choices", recipe.max_opaque_sites);
    for (auto *site : selected) mark_transition(*site, "pyobf.cff.opaque");
    return selected.size();
}

bool opaque_transition_selected(const llvm::Instruction &instruction) {
    return transition_marked(instruction, "pyobf.cff.opaque");
}

}  // namespace pyobfuscator::native::cff
