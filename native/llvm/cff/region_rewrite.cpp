#include "region.hpp"
#include "region_scope.hpp"
#include "recipe.hpp"
#include "site_report.hpp"

#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
void flatten_region(llvm::Function &function, llvm::StringRef entry, llvm::StringRef exit, unsigned seed) {
    auto recipe = resolve_recipe({}, {}, {}, "relative-tree", false, true, seed);
    recipe.seeds["cfg"] = seed;
    recipe.region_scope = std::make_shared<RegionScope>(function, entry, exit);
    stamp_site_provenance(function, "input");
    SiteCoverage coverage(function, recipe, {}, entry, exit);
    if (const auto reason = flatten_region_configured(function, recipe, coverage); !reason.empty())
        llvm::report_fatal_error(llvm::StringRef(reason));
}
}
