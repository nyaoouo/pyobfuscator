#include "cff.hpp"
#include "site_report.hpp"
#include "switch_lower_edges.hpp"

namespace pyobfuscator::native::cff {
void lower_switches(llvm::Function &function, SiteCoverage *coverage) {
    lower_switch_edges(function, coverage == nullptr ? nullptr : &coverage->origins(),
        coverage == nullptr ? nullptr : coverage->contribution_edges.get());
}
}
