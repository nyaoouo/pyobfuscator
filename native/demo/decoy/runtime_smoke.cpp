#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <thread>
#include <vector>

namespace {
using Run = int (*)(int, int, void (*)(std::uint32_t, void *), void *);
struct ObserverFailure { unsigned stage; };
struct Trace {
    unsigned stages[16]{}, count = 0, throw_stage = 0;
    Run reenter = nullptr;
    bool nested = false;
};
void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "decoy runtime check failed: %s\n", message); std::abort(); }
}
unsigned temporary_modules() {
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    require(snapshot != INVALID_HANDLE_VALUE, "module snapshot");
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    unsigned result = 0;
    if (Module32FirstW(snapshot, &entry)) do {
        if (std::wcsncmp(entry.szModule, L"pob", 3) == 0) ++result;
    } while (Module32NextW(snapshot, &entry));
    require(CloseHandle(snapshot) != 0, "module snapshot released");
    return result;
}
void observe(std::uint32_t stage, void *opaque) {
    auto &trace = *static_cast<Trace *>(opaque);
    require(trace.count < 16, "bounded observer notifications");
    trace.stages[trace.count++] = stage;
    if (trace.throw_stage == stage) throw ObserverFailure{stage};
    if (stage == 8 && trace.reenter != nullptr) {
        Trace nested;
        require(trace.reenter(0, 1, observe, &nested) == 303 && nested.count == 5, "nested independent decoy entry");
        require(temporary_modules() == 1, "nested decoy unload retains the outer decoy image");
        trace.nested = true;
    }
}
void check_trace(const Trace &trace, bool real, bool refused = false) {
#if defined(PYOBF_DEMO_POST_CODE_HASH)
    constexpr unsigned real_stages[]{1, 2, 3, 4, 5, 7, 6}, decoy_stages[]{1, 7, 8, 9, 10};
    constexpr unsigned real_count = 7;
#else
    constexpr unsigned real_stages[]{1, 2, 3, 4, 5, 6}, decoy_stages[]{1, 7, 8, 9, 10};
    constexpr unsigned real_count = 6;
#endif
    const auto *expected = real ? real_stages : decoy_stages;
    const unsigned size = refused ? 1 : real ? real_count : 5;
    require(trace.count == size, "role-specific observer count");
    for (unsigned index = 0; index != size; ++index)
        require(trace.stages[index] == expected[index], "real and decoy notifications stay separate");
}
}

int main(int argc, char **argv) {
    require(argc == 3, "outer path and environment policy supplied");
    const bool allowed = std::strcmp(argv[2], "allowed") == 0;
    const auto module = LoadLibraryA(argv[1]);
    require(module != nullptr, "outer-decoy loaded");
    const auto run = reinterpret_cast<Run>(GetProcAddress(module, "pyobf_native_demo_run"));
    require(run != nullptr && temporary_modules() == 0, "entry and initial module baseline");
    Trace normal;
    require(run(5, 0, observe, &normal) == (allowed ? 16 : 101), "ordinary accepted/denied environment result");
    check_trace(normal, allowed);
    Trace decoy, zero, negative, corrupted;
    require(run(5, 1, observe, &decoy) == 101 && run(0, 1, observe, &zero) == 303 &&
            run(-4, 1, observe, &negative) == 202, "actual decoy entry receives independent integer arguments");
    check_trace(decoy, false); check_trace(zero, false); check_trace(negative, false);
    require(run(5, 2, observe, &corrupted) == -9, "tampered decoy authentication refuses release");
    check_trace(corrupted, false, true);
    require(temporary_modules() == 0, "all ordinary and refused images retired");
    constexpr unsigned throwing_stages[]{1, 7, 8, 9, 10};
    for (auto stage : throwing_stages) {
        Trace throwing;
        throwing.throw_stage = stage;
        bool caught = false;
        try { run(5, 1, observe, &throwing); }
        catch (const ObserverFailure &error) { require(error.stage == stage, "host exception identity"); caught = true; }
        require(caught && throwing.stages[throwing.count - 1] == stage && temporary_modules() == 0,
                "observer exception propagation and mapped-image cleanup");
        Trace recovery;
        require(run(5, 1, observe, &recovery) == 101, "recovery after decoy unwind");
        check_trace(recovery, false);
    }
    Trace recursive;
    recursive.reenter = run;
    require(run(5, 1, observe, &recursive) == 101 && recursive.nested && temporary_modules() == 0,
            "nested decoy ownership and retirement");
    check_trace(recursive, false);
    std::vector<std::thread> workers;
    for (unsigned worker = 0; worker != 4; ++worker) workers.emplace_back([run, worker, allowed] {
        for (int fault : {0, 1, 2, 1}) {
            Trace trace;
            const int value = static_cast<int>(worker + 1);
            const int expected = fault == 2 ? -9 : fault == 0 && allowed ? value * 3 + 1 : 101;
            require(run(value, fault, observe, &trace) == expected, "concurrent separate real/decoy sessions");
            check_trace(trace, fault == 0 && allowed, fault == 2);
        }
    });
    for (auto &worker : workers) worker.join();
    require(temporary_modules() == 0 && FreeLibrary(module) != 0, "parallel image cleanup and outer caller lifetime");
    std::puts("actual real/decoy CNG/DLL entry, auth refusal, observer unwind, nesting and four-thread cleanup verified");
}
