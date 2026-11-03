#include "path_fold/marker.hpp"

#include <cstdio>
#include <initializer_list>

extern "C" void probe(pyobfuscator::native::path_fold::Storage &, std::uint32_t);

int main() {
    for (auto seed : {0u, 1u, 2u, 0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu}) {
        pyobfuscator::native::path_fold::Storage storage;
        probe(storage, seed);
        std::printf("%u", seed);
        for (auto word : storage.words) std::printf(" %u", word);
        std::puts("");
    }
}
