#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "measurement/capture.hpp"
#include "descriptor.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

using namespace pyobfuscator::native;
using namespace pyobfuscator::native::measurement;

namespace {
void require(bool value) { if (!value) std::exit(1); }
}

int main(int argc, char **argv) {
    require(argc == 3);
    capture_test::Parameters parameters;
    require(parameters.read(argv[1]));
    const auto module = LoadLibraryA(argv[2]);
    require(module != nullptr);
    const auto member = reinterpret_cast<platform::CodeAddress>(GetProcAddress(module, "measurement_target"));
    require(member != nullptr);
    auto warm = capture(parameters.value, member);
    require(warm.data().status == Status::ok);
    std::uint8_t expected[32]; std::memcpy(expected, warm.data().digest, 32);
    warm.reset();
    LARGE_INTEGER frequency{};
    require(QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0);
    for (unsigned owners : {1u, 4u}) {
        for (unsigned batch = 0; batch != 7; ++batch) {
            LARGE_INTEGER begin{}, end{};
            require(QueryPerformanceCounter(&begin) != 0);
            for (unsigned iteration = 0; iteration != 32; ++iteration) {
                Capture results[4];
                for (unsigned owner = 0; owner != owners; ++owner) {
                    auto input = parameters.value; input.owner += owner;
                    results[owner] = capture(input, member);
                    require(results[owner].data().status == Status::ok);
                }
                require(std::memcmp(expected, results[0].data().digest, 32) == 0);
            }
            require(QueryPerformanceCounter(&end) && end.QuadPart >= begin.QuadPart);
            std::printf("%u %.3f\n", owners,
                double(end.QuadPart - begin.QuadPart) * 1e9 / double(frequency.QuadPart) / 32.0);
        }
    }
    require(FreeLibrary(module) != 0);
}
