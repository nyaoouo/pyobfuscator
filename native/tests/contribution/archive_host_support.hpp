#pragma once

#include "pyobfuscator_native/bootstrap_binding.hpp"

extern "C" int contribution_archive_value(const pyobfuscator::native::BootstrapContextLease &, int) noexcept;

inline int archive_reference(int value) {
    const unsigned index = static_cast<unsigned>(value) & 1;
    int mixed = 0;
    for (unsigned n = 0; n != (static_cast<unsigned>(value) & 3) + 1; ++n) {
        const auto lane = (static_cast<unsigned>(value) + n) & 3;
        mixed ^= lane == 0 ? 65 : lane == 1 ? 0 : lane == 2 ? 66 : 255;
    }
    return value + mixed + (index ? 90 : 0) + (index ? 1 : 120) + (index ? 0 : 66) + index;
}
