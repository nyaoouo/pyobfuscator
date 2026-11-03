#pragma once

#include "pyobfuscator_native/environment.hpp"

namespace pyobfuscator::native::environment {

struct DetectorDefinition {
    const char *name;
    Result (*inspect)() noexcept;
};

struct DetectorCatalog {
    const DetectorDefinition *entries;
    std::size_t count;
};

// Implemented by the selected backend; never shared across backends at link time.
DetectorCatalog catalog() noexcept;

}  // namespace pyobfuscator::native::environment
