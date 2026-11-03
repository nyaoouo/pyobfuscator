#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <thread>
#include <vector>

namespace {
using Run = int (*)(int, int, void (*)(std::uint32_t, void *), void *);
void require(bool condition, const char *message) {
    if (!condition) { std::fprintf(stderr, "lifetime check failed: %s\n", message); std::exit(1); }
}
struct ObserverFailure { unsigned stage; };
struct Trace { unsigned next = 1, throw_stage = 0; Run reenter = nullptr; bool nested = false; };
#if defined(PYOBF_DEMO_POST_CODE_HASH)
constexpr unsigned final_count = 8;
unsigned position(unsigned stage) { return stage == 6 ? 7 : stage == 7 ? 6 : stage; }
#else
constexpr unsigned final_count = 7;
unsigned position(unsigned stage) { return stage; }
#endif

unsigned temporary_modules() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    require(snapshot != INVALID_HANDLE_VALUE, "module snapshot available");
    MODULEENTRY32W module{};
    module.dwSize = sizeof(module);
    unsigned count = 0;
    require(Module32FirstW(snapshot, &module) != 0, "module snapshot populated");
    do {
        if (_wcsnicmp(module.szModule, L"pob", 3) == 0 && std::wcsstr(module.szModule, L".tmp") != nullptr) ++count;
    } while (Module32NextW(snapshot, &module));
    CloseHandle(snapshot);
    return count;
}

void observe(std::uint32_t stage, void *data) {
    auto &trace = *static_cast<Trace *>(data);
    require(position(stage) == trace.next++, "ordered stage notifications");
    if (stage == 6 && !trace.nested) require(temporary_modules() == 0, "image unloaded before final notification");
    if (stage == trace.throw_stage) throw ObserverFailure{stage};
    if (stage == 4 && trace.reenter != nullptr) {
        Trace nested;
        nested.nested = true;
        require(trace.reenter(0, 0, observe, &nested) == 17 && nested.next == final_count, "reentrant independent session");
    }
}

void observe_parallel(std::uint32_t stage, void *data) {
    auto &next = *static_cast<unsigned *>(data);
    require(position(stage) == next++, "independent parallel session notifications");
}
}

int main(int argc, char **argv) {
    require(argc == 2, "outer path supplied");
    const auto module = LoadLibraryA(argv[1]);
    require(module != nullptr, "outer loaded");
    const auto run = reinterpret_cast<Run>(GetProcAddress(module, "pyobf_native_demo_run"));
    require(run != nullptr && temporary_modules() == 0, "outer entry and initial module baseline");
    for (unsigned stage = 1; stage != final_count; ++stage) {
        Trace trace;
        trace.throw_stage = stage;
        bool caught = false;
        try { run(5, 0, observe, &trace); }
        catch (const ObserverFailure &error) { require(error.stage == stage, "host exception identity preserved"); caught = true; }
        require(caught && trace.next == position(stage) + 1 && temporary_modules() == 0,
                "every observer exception cleans mapped payload and propagates");
        Trace recovery;
        require(run(5, 0, observe, &recovery) == 16 && recovery.next == final_count && temporary_modules() == 0,
                "normal entry recovers after exception cleanup");
    }
    Trace recursive;
    recursive.reenter = run;
    require(run(5, 0, observe, &recursive) == 16 && recursive.next == final_count && temporary_modules() == 0,
            "outer and nested payload providers retired independently");
    std::vector<std::thread> workers;
    for (unsigned worker = 0; worker != 4; ++worker) workers.emplace_back([run, worker] {
        for (unsigned iteration = 0; iteration != 8; ++iteration) {
            unsigned next = 1;
            const int value = static_cast<int>(worker + 1);
            require(run(value, 0, observe_parallel, &next) == value * 3 + 1 && next == final_count,
                    "four-thread separate-session execution");
        }
    });
    for (auto &worker : workers) worker.join();
    require(temporary_modules() == 0, "all concurrent payload images unloaded");
    require(FreeLibrary(module) != 0, "outer caller reference released");
    std::puts("actual owned DLL lifetime verified");
}
