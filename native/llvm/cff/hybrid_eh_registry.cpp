#include "hybrid_eh.hpp"

namespace pyobfuscator::native::cff {

bool hybrid_component_supported(llvm::StringRef name) {
    for (const auto supported : {"cfg", "call-frames", "external-calls", "call-preparation",
                               "reference-routes", "import-routes", "indexed-locals", "path-fold", "runtime-contribution",
                               "opaque-choices", "reachable-junk", "decoy-transitions", "bogus-clones", "bogus-synthesis",
                               "integer-literals", "comparison-constants", "constant-archive",
                               "common-exit", "deduplicate-blocks", "split-blocks"})
        if (name == supported) return true;
    return false;
}

}  // namespace pyobfuscator::native::cff
