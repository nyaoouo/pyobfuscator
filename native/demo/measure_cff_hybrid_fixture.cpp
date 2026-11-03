namespace {
struct Guard {
    int *effects;
    ~Guard() { ++*effects; }
};

__attribute__((noinline)) int measure_leaf(int input, int mode) {
    if (mode != 0) throw input + 23;
    return input * 3 + 7;
}
}

extern "C" __declspec(dllexport) __attribute__((noinline))
int hybrid_measure(int input, int mode, int *effects) {
    Guard guard{effects};
    try {
        const auto value = measure_leaf(input, mode);
        if (input < 0) return value - 5;
        return value + 9;
    } catch (int error) {
        *effects += 8;
        if (mode == 2) throw;
        return error * 2;
    }
}
