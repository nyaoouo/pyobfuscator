#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "measurement/capture.hpp"
#include "measurement/internal.hpp"
#include "descriptor.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <utility>

namespace {
using namespace pyobfuscator::native;
using namespace pyobfuscator::native::measurement;
const unsigned char data_anchor[8] = {1, 2, 3, 4, 5, 6, 7, 8};

void require(bool condition, const char *message) {
    if (!condition) { std::fprintf(stderr, "native capture probe: %s\n", message); std::exit(1); }
}
bool blank(const Data &data) {
    if (data.kind || data.owner || data.subject ||
            data.frequency || data.read_started || data.read_completed) return false;
    for (auto byte : data.digest) if (byte) return false;
    return true;
}
bool empty(const Data &data) { return data.status == Status::unavailable && blank(data); }
void row(const Data &data) {
    require(data.status == Status::ok && data.frequency && data.read_completed >= data.read_started, "capture status/interval");
    std::printf("capture %u %u %u %llu %llu %llu ", data.owner, data.subject, data.kind,
        static_cast<unsigned long long>(data.frequency), static_cast<unsigned long long>(data.read_started),
        static_cast<unsigned long long>(data.read_completed));
    for (auto byte : data.digest) std::printf("%02x", static_cast<unsigned>(byte));
    std::puts("");
}
bool mapped(platform::CodeAddress address) {
    HMODULE module = nullptr;
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(address), &module) != 0;
}
void actual_failures(const Descriptor &input, platform::CodeAddress member, const void *data_address, HMODULE image) {
    auto unavailable = capture(input, nullptr);
    require(unavailable.data().status == Status::unavailable && blank(unavailable.data()), "missing actual module refusal");
    auto changed = input; --changed.image_size;
    auto mismatch = capture(changed, member);
    require(mismatch.data().status == Status::invalid_descriptor && blank(mismatch.data()), "actual image identity mismatch");
    const auto base = reinterpret_cast<std::uintptr_t>(image);
    const auto address = reinterpret_cast<std::uintptr_t>(data_address);
    require(address >= base && address - base < input.image_size, "non-code test data belongs to target");
    const Range range{static_cast<std::uint32_t>(address - base), 8};
    changed = input; changed.ranges = &range; changed.range_count = 1; changed.fixups = nullptr; changed.fixup_count = 0;
    auto non_code = capture(changed, member);
    require(non_code.data().status == Status::read_failed && blank(non_code.data()), "non-executable image data refusal");
    if (input.kind == 1) {
        DWORD previous = 0, ignored = 0;
        require(VirtualProtect(reinterpret_cast<void *>(member), 1, PAGE_EXECUTE_READWRITE, &previous) != 0,
            "prepare writable-code availability test");
        auto writable = capture(input, member);
        const bool restored = VirtualProtect(reinterpret_cast<void *>(member), 1, previous, &ignored) != 0;
        require(restored, "restore executable page protection");
        require(writable.data().status == Status::read_failed && blank(writable.data()), "writable executable page refusal");
    }
}
}

extern "C" __declspec(dllexport) int measurement_anchor(int input) {
    volatile int value = input;
    return value * 3 + 5;
}

int main(int argc, char **argv) {
    require(argc == 3 || argc == 4, "mode and descriptor supplied");
    capture_test::Parameters parameters;
    require(parameters.read(argv[2]), "bounded private test descriptor");
    const bool dll = std::strcmp(argv[1], "dll") == 0;
    require(dll == (argc == 4), "image supplied only in DLL mode");
    HMODULE image = nullptr;
    platform::CodeAddress member = reinterpret_cast<platform::CodeAddress>(&measurement_anchor);
    if (dll) {
        image = LoadLibraryA(argv[3]); require(image != nullptr, "load test DLL");
        member = reinterpret_cast<platform::CodeAddress>(GetProcAddress(image, "measurement_target"));
        require(member != nullptr, "resolve actual DLL member");
    }
    auto input = parameters.value;
    auto first = capture(input, member);
    if (first.data().status != Status::ok) {
        std::fprintf(stderr, "capture status=%u kind=%u size=%u ranges=%u fixups=%u\n",
            static_cast<unsigned>(first.data().status), input.kind, input.image_size, input.range_count, input.fixup_count);
        std::size_t material_size = 0;
        ModuleView diagnostic{};
        const auto opened = PYOBF_NATIVE_OPEN_CODE_VIEW(member, diagnostic);
        std::fprintf(stderr, "preflight=%u open=%u full=%u expected=%llx actual=%llx sizes=%u/%u sections=%u\n",
            static_cast<unsigned>(detail::validate(input, nullptr, material_size)), static_cast<unsigned>(opened),
            static_cast<unsigned>(detail::validate(input, &diagnostic, material_size)),
            static_cast<unsigned long long>(input.preferred_base), static_cast<unsigned long long>(diagnostic.header_base),
            input.image_size, diagnostic.image_size, diagnostic.section_count);
        require(PYOBF_NATIVE_CLOSE_CODE_VIEW(diagnostic), "diagnostic module close");
    }
    require(first.data().status == Status::ok, "first actual code capture");
    ++input.owner;
    auto second = capture(input, member);
    require(second.data().status == Status::ok, "second actual code capture");
    require(std::memcmp(first.data().digest, second.data().digest, 32) != 0, "separate owner domains");
    const auto data_address = dll ? reinterpret_cast<const void *>(GetProcAddress(image, "measurement_data")) : data_anchor;
    require(data_address != nullptr, "resolve non-code fixture data");
    actual_failures(input, member, data_address, dll ? image : GetModuleHandleW(nullptr));
    auto moved = std::move(first);
    require(empty(first.data()), "move constructor retired source");
    auto assigned = capture(input, member);
    require(assigned.data().status == Status::ok, "move assignment replacement setup");
    assigned = std::move(moved);
    require(empty(moved.data()), "move assignment retired source");
    row(assigned.data()); row(second.data());
    if (dll) { require(FreeLibrary(image) != 0, "release original DLL reference"); image = nullptr; }
    require(mapped(member), "captures retain target after caller releases it");
    Data concurrent[4]{};
    std::thread workers[4];
    for (unsigned index = 0; index != 4; ++index) workers[index] = std::thread([&, index] {
        auto own = parameters.value; own.owner += index + 2;
        auto result = capture(own, member);
        concurrent[index] = result.data();
    });
    for (auto &worker : workers) worker.join();
    for (const auto &data : concurrent) row(data);
    assigned.reset(); require(empty(assigned.data()) && mapped(member), "first reset preserves other lease");
    second.reset(); require(empty(second.data()), "second reset clears snapshot");
    if (dll) require(!mapped(member), "last target lease unloads the DLL");
    std::puts("ownership-concurrency-verified");
}
