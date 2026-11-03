#include "pyobfuscator_native/system_ops.hpp"

#include <array>
#include <atomic>
#include <cstdio>
#include <initializer_list>
#include <limits>
#include <thread>

int main() {
    std::array<std::uint8_t, 65536> bytes{};
    std::array<std::uint8_t, 32> digest{};
    std::array<std::uint8_t, 32> empty{};
    for (const unsigned length : {0u, 1u, 3u, 55u, 56u, 63u, 64u, 65u, 127u, 128u, 129u, 1024u, 4096u, 65536u}) {
        for (unsigned index = 0; index != length; ++index)
            bytes[index] = static_cast<std::uint8_t>(index * 131u + length * 17u);
        if (!PYOBF_NATIVE_SHA256(length == 0 ? nullptr : bytes.data(), length, digest.data())) return 1;
        if (length == 0) empty = digest;
        std::printf("%u ", length);
        for (auto byte : digest) std::printf("%02x", byte);
        std::puts("");
    }
    std::atomic<bool> correct{true};
    std::array<std::thread, 4> workers;
    for (auto &worker : workers) worker = std::thread([&] {
        std::array<std::uint8_t, 32> local;
        for (unsigned attempt = 0; attempt != 16; ++attempt)
            if (!PYOBF_NATIVE_SHA256(nullptr, 0, local.data()) || local != empty) correct.store(false);
    });
    for (auto &worker : workers) worker.join();
    if (!correct.load()) return 4;
    for (unsigned attempt = 0; attempt != 3; ++attempt) {
        if (attempt == 2 && sizeof(std::size_t) <= sizeof(std::uint32_t)) continue;
        digest.fill(0xcc);
        const auto length = attempt == 2 ?
            static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()) + 1 : 1;
        if (PYOBF_NATIVE_SHA256(attempt == 0 ? nullptr : bytes.data(), length,
                               attempt == 1 ? nullptr : digest.data())) return 2;
        if (attempt != 1) for (auto byte : digest) if (byte != 0) return 3;
    }
}
