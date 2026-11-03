#include "bogus_blocks.hpp"

#include "junk_expression.hpp"
#include "site_provenance.hpp"
#include "site_report.hpp"
#include "transition_sites.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_bogus_synthesis_sites(llvm::Function &function,
                                                            const ResolvedRecipe &recipe) {
    return discover_transition_sites(function, bogus_quota(recipe, "bogus-synthesis"),
                                       recipe.seeds.at("bogus-synthesis"));
}

unsigned prepare_bogus_synthesis(llvm::Function &function, llvm::Value *state_slot,
                                  const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    const auto remaining = recipe.max_bogus_blocks - coverage.bogus_clone_blocks;
    const auto nominal = bogus_quota(recipe, "bogus-synthesis");
    coverage.preparation_metric("bogus-synthesis", "quota", nominal);
    coverage.preparation_metric("bogus-synthesis", "available_after_clones", remaining);
    if (nominal == 0 && recipe.requirement("bogus-synthesis") == Requirement::required) return 0;
    const auto sites = select_bogus_sites(coverage, "bogus-synthesis", remaining);
    coverage.preparation_metric("bogus-synthesis", "fallback_blocks",
                                sites.size() > nominal ? sites.size() - nominal : 0);
    for (auto *site : sites) {
        const auto placed = create_bogus_block(*site, "bogus-synthesis", coverage, state_slot, recipe.seeds.at("bogus-synthesis"));
        const auto salt = component_seed(recipe.seeds.at("bogus-synthesis"), function.getName(),
                                          instruction_provenance(*placed.guard));
        llvm::IRBuilder<> builder(placed.body->getTerminator());
        auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.synthesis.state");
        mark_bogus_result(emit_junk_mix(builder, state, salt, recipe.synthesis_rounds), state_slot, coverage);
        mark_transition(*placed.body->getTerminator(), "pyobf.cff.bogus-synthesis.work");
        ++coverage.bogus_synthesis_blocks;
    }
    coverage.preparation_metric("bogus-synthesis", "selected_blocks", sites.size());
    return sites.size();
}

unsigned bind_bogus_synthesis(llvm::BasicBlock &body, llvm::Value *state_slot, std::uint32_t,
                               std::uint32_t salt, SiteCoverage *coverage) {
    return bind_bogus_block(body, state_slot, salt, coverage, "bogus-synthesis");
}

}  // namespace pyobfuscator::native::cff
