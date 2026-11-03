#include "contribution_gate.hpp"
#include "contribution_private.hpp"
#include "site_report.hpp"
#include "contribution_edges.hpp"
#include "region_scope.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
unsigned normalize_contribution_sites(llvm::Function &function, const ResolvedRecipe &recipe,
    SiteCoverage &coverage) {
    if (recipe.contribution && recipe.contribution->schema == 3 &&
            recipe.contribution_options.selection == ContributionSelection::original_edges)
        llvm::report_fatal_error("mixed site providers require explicit contribution points");
    const auto sites = discover_contribution_sites(function, recipe);
    if (recipe.contribution_options.selection == ContributionSelection::original_edges) {
        coverage.contribution_edges = std::make_shared<ContributionEdgePlan>(function, recipe);
        if (const auto reason = coverage.contribution_edges->failure(); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(reason));
        unsigned selected = 0;
        for (const auto &edge : coverage.contribution_edges->edges()) selected += edge.selected;
        if (!coverage.contribution_edges->deferred()) coverage.contribution_edges->instrument(function, coverage.origins());
        coverage.preparation_metric("runtime-contribution", "original_edges", coverage.contribution_edges->edges().size());
        coverage.preparation_metric("runtime-contribution", "selected_original_edges", selected);
    }
    for (const auto &site : sites) {
        if (!site.reason.empty()) llvm::report_fatal_error(llvm::StringRef(site.reason));
        auto *marker = llvm::cast<llvm::CallInst>(site.instruction);
        auto *body = marker->getParent();
        const auto role = coverage.origins().get(*body);
        auto *continuation = body->splitBasicBlock(marker->getNextNode(), "pyobf.contribution.continue");
        if (recipe.region_scope) recipe.region_scope->adopt(*continuation);
        coverage.origins().set(*body, BlockRole::routing);
        coverage.origins().set(*continuation, role);
    }
    coverage.preparation_metric("runtime-contribution", "explicit_gateways", sites.size());
    return sites.size();
}
}
