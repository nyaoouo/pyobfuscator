#include "preparation.hpp"

#include "cff.hpp"
#include "mutation_guard.hpp"
#include "recipe.hpp"
#include "site_report.hpp"
#include "region.hpp"
#include "region_scope.hpp"

#include "llvm/IR/Function.h"

namespace pyobfuscator::native::cff {

std::string prepare_components(llvm::Function &function, llvm::Value *state_slot,
                                 const ResolvedRecipe &recipe, SiteCoverage &coverage,
                                 llvm::ArrayRef<const llvm::BasicBlock *> excluded) {
    coverage.freeze_prepared_sites(function, excluded);
    bool structural_change = false;
    for (const auto &component : registered_components()) {
        if (!recipe.enabled(component.name) || component.prepare == nullptr) continue;
        const CfgSeal seal(function);
        std::vector<const llvm::BasicBlock *> before;
        for (const auto &block : function) before.push_back(&block);
        const auto prepared = component.prepare(function, state_slot, recipe, coverage);
        std::string reason = component.changes_cfg && !recipe.region_scope ? seal.check_definitions(function) : seal.check(function);
        if (reason.empty()) reason = coverage.origins().validate_new_blocks(function, before);
        if (!reason.empty()) return std::string(component.name) + ": " + reason;
        structural_change |= component.changes_cfg && prepared != 0 && !recipe.region_scope;
    }
    if (structural_change) lower_cross_block_ssa(function, &coverage);
    return recipe.region_scope ? validate_relative_tree_region(function,
        recipe.region_scope->entry_name(), recipe.region_scope->exit_name()) : validate_configured(function, recipe);
}

}  // namespace pyobfuscator::native::cff
