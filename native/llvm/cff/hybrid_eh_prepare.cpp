#include "hybrid_eh.hpp"
#include "site_report.hpp"

namespace pyobfuscator::native::cff {
HybridEhPlan prepare_hybrid_eh(llvm::Function &function, SiteCoverage &coverage) {
    return prepare_hybrid_eh_edges(function, coverage.origins(), coverage.contribution_edges.get());
}
}
