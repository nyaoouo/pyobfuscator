#include <cstdio>

struct Guard {
    int *effects;
    int amount;
    ~Guard() { *effects += amount; }
};

__attribute__((noinline)) int may_throw(int input) {
    if (input < 0) throw input;
    return input * 3 + 1;
}

extern "C" __attribute__((noinline)) int hybrid_case(int input, int *effects) {
    Guard outer{effects, 1};
    try {
        int value = may_throw(input);
        Guard inner{effects, 4};
        if (input == 4) throw 9;
        if (input == 5) value += hybrid_case(2, effects);
        for (int i = 0; i < (input & 3); ++i) value += may_throw(i + 1);
        return value;
    } catch (int error) {
        *effects += 16;
        if (error == -2) throw;
        return error * 2;
    }
}

extern "C" __attribute__((noinline)) int hybrid_straight(int input) noexcept {
    return may_throw(input);
}

int main() {
    for (int input = -5; input <= 7; ++input) {
        int effects = 0, value;
        try { value = hybrid_case(input, &effects); }
        catch (int error) { value = error + 1000; }
        std::printf("%d:%d:%d\n", input, value, effects);
    }
    for (int input = 0; input < 3; ++input) std::printf("plain:%d\n", hybrid_straight(input));
}
