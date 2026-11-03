#include <cstdio>
#include <stdexcept>
#include <string>

extern "C" int frame_cpp_values(int);
extern "C" int frame_throwing_caller(int);

int main() {
    for (int value = 0; value < 40; ++value) {
        if (frame_cpp_values(value) != value + 31 || frame_throwing_caller(value) != value * 3 + 9) return 1;
    }
    try {
        frame_throwing_caller(-1);
        return 2;
    } catch (const std::runtime_error &error) {
        if (std::string(error.what()) != "frame-unwind-token") return 3;
    }
    std::puts("C++ frame ABI and propagation verified");
    return 0;
}
