#include "pyobfuscator_native/system_ops.hpp"

#include <array>
#include <cstdlib>
#include <cstring>

namespace {
unsigned allocations = 0, erasures = 0;
std::uint8_t *expected_output = nullptr;
}
namespace pyobfuscator::native::platform {
void *allocate(std::size_t size) noexcept {
    if (size == 0) std::abort();
    ++allocations;
    return nullptr;
}
void release(void *) noexcept { std::abort(); }
void erase(void *memory, std::size_t length) noexcept {
    if (memory != expected_output || length != 32) std::abort();
    std::memset(memory, 0, length);
    ++erasures;
}
}

int main() {
    std::array<std::uint8_t, 32> output;
    for (unsigned attempt = 0; attempt != 16; ++attempt) {
        output.fill(0xcc);
        expected_output = output.data();
        if (PYOBF_NATIVE_SHA256(nullptr, 0, output.data())) return 1;
        for (auto byte : output) if (byte != 0) return 2;
        if (allocations != attempt + 1 || erasures != attempt + 1) return 3;
    }
}
