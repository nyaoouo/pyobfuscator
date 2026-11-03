#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstring>

namespace {

struct Trace {
    std::uint32_t stages[8]{};
    unsigned count = 0;
};

void observe(std::uint32_t stage, void *opaque) {
    auto *trace = static_cast<Trace *>(opaque);
    if (trace->count < 8) {
        trace->stages[trace->count++] = stage;
    }
}

bool matches(const Trace &trace, const std::uint32_t *expected, unsigned size) {
    if (trace.count != size) {
        return false;
    }
    for (unsigned index = 0; index < size; ++index) {
        if (trace.stages[index] != expected[index]) {
            return false;
        }
    }
    return true;
}

}  // namespace

int main(int argc, char *argv[]) {
    if (argc != 2 && argc != 3) {
        return 2;
    }
    auto *module = LoadLibraryA(argv[1]);
    if (module == nullptr) {
        return 3;
    }
    using Run = int (*)(int, int, void (*)(std::uint32_t, void *), void *);
    auto *run = reinterpret_cast<Run>(GetProcAddress(module, "pyobf_native_demo_run"));
    if (run == nullptr) {
        FreeLibrary(module);
        return 4;
    }

    if (argc == 3 && std::strcmp(argv[2], "triggered") == 0) {
        Trace blocked{};
        const bool okay = run(5, 0, observe, &blocked) == -2 &&
                          blocked.count == 1 && blocked.stages[0] == 1;
        FreeLibrary(module);
        return okay ? 0 : 5;
    }

    constexpr std::uint32_t stages[]{1, 2, 3, 4, 5, 6};
    constexpr std::uint32_t post_stages[]{1, 2, 3, 4, 5, 7, 6};
    const bool post = argc == 3 && std::strcmp(argv[2], "post") == 0;
    const auto *wanted = post ? post_stages : stages;
    const unsigned wanted_count = post ? 7 : 6;
    Trace positive{};
    Trace zero{};
    Trace negative{};
    Trace corrupted{};
    const bool okay = run(5, 0, observe, &positive) == 16 &&
                      run(0, 0, observe, &zero) == 17 &&
                      run(-4, 0, observe, &negative) == 15 &&
                      run(5, 1, observe, &corrupted) == -4 &&
                      matches(positive, wanted, wanted_count) && matches(zero, wanted, wanted_count) &&
                      matches(negative, wanted, wanted_count) && corrupted.count == 1 &&
                      corrupted.stages[0] == 1;
    FreeLibrary(module);
    return okay ? 0 : 5;
}
