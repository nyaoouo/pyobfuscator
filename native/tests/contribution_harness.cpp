#include "contribution/value.hpp"

#include <cstdio>
#include <fstream>

extern "C" std::uint32_t contribution_delta_0(std::uint32_t, std::uint32_t);
extern "C" std::uint32_t contribution_delta_1(std::uint32_t, std::uint32_t);
extern "C" std::uint32_t contribution_delta_2(std::uint32_t, std::uint32_t);
extern "C" std::uint32_t contribution_mix_1(std::uint32_t, std::uint32_t, std::uint32_t);
extern "C" std::uint32_t contribution_mix_2(std::uint32_t, std::uint32_t, std::uint32_t);
extern "C" std::uint32_t contribution_mix_3(std::uint32_t, std::uint32_t, std::uint32_t);

namespace {
bool matches(std::istream &input, const pyobfuscator::native::contribution::State &state) {
    std::uint32_t left, right, count;
    return bool(input >> left >> right >> count) && left == state.left && right == state.right && count == state.words;
}
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    std::ifstream input(argv[1]);
    if (!input) return 2;
    using namespace pyobfuscator::native;
    unsigned cases;
    if (!(input >> cases)) return 3;
    for (unsigned index = 0; index != cases; ++index) {
        std::uint32_t domain, function, site;
        unsigned sources;
        if (!(input >> domain >> function >> site >> sources)) return 4;
        auto state = contribution::initialize(domain, function, site);
        if (!matches(input, state)) return 5;
        for (unsigned source = 0; source != sources; ++source) {
            std::uint32_t label, encoding;
            unsigned words;
            if (!(input >> label >> encoding >> words)) return 6;
            state = contribution::source(state, label, encoding, words);
            if (!matches(input, state)) return 7;
            for (unsigned word = 0; word != words; ++word) {
                std::uint32_t value;
                if (!(input >> value)) return 8;
                state = contribution::word(state, value);
                if (!matches(input, state)) return 9;
            }
        }
        std::uint32_t expected;
        if (!(input >> expected) || contribution::finish(state) != expected) return 10;
    }
    using Delta = std::uint32_t (*)(std::uint32_t, std::uint32_t);
    constexpr Delta deltas[]{contribution_delta_0, contribution_delta_1, contribution_delta_2};
    for (unsigned index = 0; index != 3; ++index) {
        std::uint32_t initial, target, reference, salt, transition_salt;
        unsigned count;
        if (!(input >> initial >> target >> reference >> salt >> transition_salt >> count)) return 11;
        const auto encoded = (target - initial) ^ path_fold::mix(initial ^ transition_salt);
        const auto sealed = contribution::seal(encoded, reference, salt);
        for (unsigned row = 0; row != count; ++row) {
            std::uint32_t current, observed, expected;
            if (!(input >> current >> observed >> expected)) return 12;
            const auto actual = contribution::unseal(sealed, observed, salt) ^ path_fold::mix(current ^ transition_salt);
            if (deltas[index](current, observed) != expected || actual != expected) return 13;
        }
    }
    using Mix = std::uint32_t (*)(std::uint32_t, std::uint32_t, std::uint32_t);
    constexpr Mix mixes[]{contribution_mix_1, contribution_mix_2, contribution_mix_3};
    for (unsigned group = 0; group != 3; ++group) {
        unsigned count;
        if (!(input >> count)) return 15;
        for (unsigned row = 0; row != count; ++row) {
            std::uint32_t a, b, c, expected;
            if (!(input >> a >> b >> c >> expected)) return 16;
            if (mixes[group](a, b, c) != expected) return 17;
            auto state = contribution::initialize(77, 13, 101);
            const std::uint32_t values[]{a, b, c};
            for (unsigned index = 0; index <= group; ++index) {
                state = contribution::source(state, 17 + index * 12, 1, 1);
                state = contribution::word(state, values[index]);
            }
            if (contribution::finish(state) != expected) return 18;
        }
    }
    char extra;
    if (input >> extra) return 14;
    std::puts("contribution v1 host/runtime/emitted correction verified");
}
