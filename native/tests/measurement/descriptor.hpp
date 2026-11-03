#pragma once

#include "measurement/types.hpp"

#include <cstdio>
#include <vector>

namespace capture_test {
struct Parameters {
    pyobfuscator::native::measurement::Descriptor value{};
    std::vector<pyobfuscator::native::measurement::Range> ranges;
    std::vector<std::uint32_t> fixups;
    bool read(const char *path);
};
}
