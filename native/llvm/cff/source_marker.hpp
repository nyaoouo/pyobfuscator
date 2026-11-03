#pragma once

#include "path_fold_marker.hpp"

namespace pyobfuscator::native::cff {
inline bool source_marker_name(llvm::StringRef name) {
    return path_fold_marker_name(name) || name == "pyobf_native_contribution_site_v1" ||
        name == "pyobf_native_measured_contribution_site_v1" ||
        name == "pyobf_native_mixed_contribution_site_v1";
}
}
