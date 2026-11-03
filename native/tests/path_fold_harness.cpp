#include "path_fold/value.hpp"

#include <cstdio>
#include <fstream>

extern "C" void fold_initial(std::uint32_t *, std::uint32_t);
extern "C" void fold_step(std::uint32_t *, std::uint32_t, std::uint32_t);
extern "C" std::uint32_t fold_bound(std::uint32_t);

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    std::ifstream input(argv[1]);
    if (!input) return 2;
    using namespace pyobfuscator::native::path_fold;
    unsigned cases;
    if (!(input >> cases)) return 3;
    for (unsigned index = 0; index != cases; ++index) {
        std::uint32_t seed;
        unsigned steps;
        if (!(input >> seed >> steps)) return 4;
        auto reference = initialize(seed);
        State actual{}, expected{};
        fold_initial(actual.data(), seed);
        for (auto &value : expected) if (!(input >> value)) return 5;
        if (actual != expected || reference != expected) return 6;
        for (unsigned step = 0; step != steps; ++step) {
            std::uint32_t tag, word;
            if (!(input >> tag >> word)) return 7;
            for (auto &value : expected) if (!(input >> value)) return 8;
            reference = advance(reference, tag, word);
            fold_step(actual.data(), tag, word);
            if (actual != expected || reference != expected) return 9;
        }
        const auto bytes = serialize(actual);
        for (auto byte : bytes) {
            unsigned expected_byte;
            if (!(input >> expected_byte) || expected_byte != byte) return 14;
        }
    }
    unsigned bindings;
    if (!(input >> bindings)) return 10;
    for (unsigned index = 0; index != bindings; ++index) {
        std::uint32_t current, expected;
        if (!(input >> current >> expected)) return 11;
        constexpr auto encoded = encode_word(0x13579bdfu, 0x2468ace0u, 0x5a91c37du);
        if (fold_bound(current) != expected || decode_word(encoded, current, 0x5a91c37du) != expected)
            return 12;
    }
    char extra;
    if (input >> extra) return 13;
    std::puts("path-fold v1 host/runtime/emitter verified");
}
