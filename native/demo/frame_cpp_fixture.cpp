#include <cstdint>
#include <cstring>
#include <stdexcept>

struct alignas(16) Sample {
    std::uint64_t number;
    double floating;
};

__attribute__((noinline)) static Sample typed_leaf(Sample sample, int input) noexcept {
    sample.number += static_cast<std::uint64_t>(input);
    return sample;
}

__attribute__((noinline)) static int throwing_leaf(int input) {
    if (input < 0) throw std::runtime_error("frame-unwind-token");
    return input * 3;
}

extern "C" __attribute__((noinline)) int frame_cpp_values(int input) noexcept {
    const Sample sample{31, -0.0};
    const auto result = typed_leaf(sample, input);
    std::uint64_t bits;
    std::memcpy(&bits, &result.floating, sizeof(bits));
    return bits == 0x8000000000000000ull ? static_cast<int>(result.number) : -10000;
}

extern "C" __attribute__((noinline)) int frame_throwing_caller(int input) {
    return throwing_leaf(input) + 9;
}
