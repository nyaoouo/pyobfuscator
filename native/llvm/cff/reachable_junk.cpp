#include "recipe.hpp"

#include "junk_expression.hpp"
#include "site_provenance.hpp"
#include "site_report.hpp"
#include "transition_sites.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_junk_sites(llvm::Function &function,
                                                const ResolvedRecipe &recipe) {
    return discover_transition_sites(function, recipe.max_junk_sites, recipe.seeds.at("reachable-junk"));
}

unsigned prepare_reachable_junk(llvm::Function &, llvm::Value *, const ResolvedRecipe &recipe,
                                 SiteCoverage &coverage) {
    const auto selected = select_prepared_sites(coverage, "reachable-junk", recipe.max_junk_sites);
    for (auto *site : selected) mark_transition(*site, "pyobf.cff.junk");
    return selected.size();
}

bool junk_transition_selected(const llvm::Instruction &instruction) {
    return transition_marked(instruction, "pyobf.cff.junk");
}

}  // namespace pyobfuscator::native::cff
