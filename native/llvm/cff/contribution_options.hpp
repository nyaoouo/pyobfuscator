#pragma once

#include <optional>
#include "llvm/Support/JSON.h"

namespace pyobfuscator::native::cff {
enum class ContributionSelection { explicit_points, original_edges };
struct ContributionOptions {
    ContributionSelection selection = ContributionSelection::explicit_points;
    unsigned minimum_edges = 1, minimum_percent = 100, maximum_edges = 256;
};
struct ContributionOverride {
    std::optional<ContributionSelection> selection;
    std::optional<unsigned> minimum_edges, minimum_percent, maximum_edges;
};
ContributionOverride read_contribution_options(const llvm::json::Value &);
void apply_contribution_options(ContributionOptions &, const ContributionOverride &);
llvm::json::Object describe_contribution_options(const ContributionOptions &);
}
