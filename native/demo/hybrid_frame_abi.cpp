#include <cstdint>
#include <cstdio>

struct Large { std::uint64_t words[6]; };
struct Small { int x, y; };
struct Guard {
    int *effects;
    ~Guard() { ++*effects; }
};

extern "C" __attribute__((noinline)) Large aggregate_target(Large value, int input) {
    if (input < 0) throw input;
    for (unsigned i = 0; i < 6; ++i) value.words[i] += static_cast<unsigned>(input + i);
    return value;
}

extern "C" __attribute__((noinline)) Small small_target(Small value, int input) {
    if (input == 3) throw 31;
    return {value.x + input, value.y - input};
}

extern "C" __attribute__((noinline)) int hybrid_abi(int input, int *effects) {
    Guard guard{effects};
    try {
        Large value{{11, 19, 23, 29, 31, 41}};
        auto result = aggregate_target(value, input);
        auto small = small_target({7, 13}, input);
        return static_cast<int>(result.words[2] + result.words[5]) + small.x * 3 + small.y;
    } catch (int error) {
        *effects += 8;
        return 100 + error;
    }
}

int main() {
    for (int input = -3; input <= 7; ++input) {
        int effects = 0;
        const auto value = hybrid_abi(input, &effects);
        if (effects != (input < 0 || input == 3 ? 9 : 1)) return 1;
        std::printf("%d:%d:%d\n", input, value, effects);
    }
}
