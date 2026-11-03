#include "release/record.hpp"

#include <cstdio>

int main() {
    const auto *bytes = reinterpret_cast<const unsigned char *>(&pyobfuscator::native::release::record);
    for (unsigned index = 0; index != sizeof(pyobfuscator::native::release::Record); ++index)
        std::printf("%02x", bytes[index]);
    std::puts("");
}
