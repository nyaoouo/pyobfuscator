#pragma once

#include "llvm/ADT/StringRef.h"

namespace pyobfuscator::native::cff {
inline bool path_fold_marker_name(llvm::StringRef name) {
    return name == "pyobf_native_path_fold_init_v1" || name == "pyobf_native_path_fold_step_v1";
}
}
