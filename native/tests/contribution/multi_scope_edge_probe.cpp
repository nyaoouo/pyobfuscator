#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "context/runtime.hpp"
#include "contribution/scope.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

namespace native = pyobfuscator::native;
namespace scoped = native::contribution::scoped;
namespace observer = native::measurement::observer;
extern "C" int multi_scope_edge_body(scoped::Scope &, scoped::Scope &, int) noexcept(false);
extern "C" int edge_scope_negative(int value) noexcept { return -value + 11; }
extern "C" int edge_scope_zero(int) noexcept { return 17; }
extern "C" int edge_scope_positive(int value) noexcept { return value * 3 + 1; }

namespace {
std::uint64_t generation = 0, instance = 0;
std::uintptr_t context = 0;
unsigned admissions = 0, effects = 0, first_admissions = 0, second_admissions = 0;
bool negative = false;
void require(bool condition, const char *reason) {
    if (!condition) { std::fprintf(stderr, "site scope: %s\n", reason); std::exit(1); }
}
std::vector<std::uint8_t> read(const char *path) {
    auto *stream = std::fopen(path, "rb"); require(stream != nullptr, "input open");
    std::vector<std::uint8_t> bytes;
    for (int value; (value = std::fgetc(stream)) != EOF;) {
        require(bytes.size() < 512 * 1024, "input size");
        bytes.push_back(static_cast<std::uint8_t>(value));
    }
    require(!std::ferror(stream) && std::fclose(stream) == 0, "input read");
    return bytes;
}
native::BootstrapContextResult dispatch(const native::BootstrapContextRequest &request, void *) noexcept {
    if (request.operation_id != 0x1020 || request.input == nullptr || request.input_size != sizeof(scoped::Admission))
        return {native::BootstrapContextStatus::invalid_request, 0};
    scoped::Admission message{};
    std::memcpy(&message, request.input, sizeof(message));
    if (message.version != scoped::admission_version || message.size != sizeof(message) || message.reserved != 0 ||
            message.routing != 0x1020 || message.domain != 1 || message.function != 7 ||
            (message.source != 13 && message.source != 29) || message.observation_owner != 7 ||
            message.generation != generation || message.observation_instance != instance ||
            message.observation_context != context)
        return {native::BootstrapContextStatus::context_mismatch, 0};
    ++admissions;
    if (message.source == 13) ++first_admissions;
    else ++second_admissions;
    return {native::BootstrapContextStatus::ok, generation};
}
}

extern "C" int site_scope_effect(scoped::Scope &first, scoped::Scope &second, int result) noexcept(false) {
    ++effects;
    if (negative) std::exit(91);
    require(first.observation().sequence != 0 && second.observation().sequence != 0 &&
        first.observation().sequence != second.observation().sequence &&
        first.observation().identity.owner == 7 && second.observation().identity.owner == 7,
        "two sites did not retain distinct live snapshots");
    return result;
}

int main(int argc, char **argv) {
    require(argc == 5 || argc == 6, "metadata/reference/material/DLL inputs");
    const auto mode = argc == 6 ? argv[5] : "normal";
    require(std::strcmp(mode, "normal") == 0 || std::strcmp(mode, "swapped") == 0 ||
        std::strcmp(mode, "wrong-spec") == 0 ||
        std::strcmp(mode, "bad-snapshot") == 0 || std::strcmp(mode, "bad-material") == 0,
        "unknown negative mode");
    negative = std::strcmp(mode, "normal") != 0;
    const auto metadata = read(argv[1]), reference = read(argv[2]), material = read(argv[3]);
    require(metadata.size() == 84 && material.size() == scoped::material_bytes, "fixed reference inputs");
    native::measurement::reference::Identity identity{};
    native::path_fold::Storage fold{};
    std::memcpy(&identity, metadata.data(), sizeof(identity));
    std::memcpy(fold.words, metadata.data() + sizeof(identity), sizeof(fold.words));
    require(identity.stage == 2 && identity.owner == 7, "post-release reference identity");
    auto *module = LoadLibraryA(argv[4]); require(module != nullptr, "actual subject DLL load");
    auto *subject = GetProcAddress(module, "measurement_target"); require(subject != nullptr, "subject entry");
    auto parent = native::create_bootstrap_context({native::bootstrap_context_abi_version, dispatch, nullptr, nullptr});
    require(parent.status == native::BootstrapContextStatus::ok, "parent creation");
    generation = parent.owner.generation();
    auto parent_lease = parent.owner.lease();
    auto binding = native::bind_bootstrap_context(parent_lease);
    require(binding.status == native::BootstrapContextStatus::ok, "strict parent publication");
    auto observed = observer::create(reference.data(), reference.size(), identity, fold.words,
        {{observer::Mode::per_use, 10000000000ull, 10000000000ull},
            reinterpret_cast<native::platform::CodeAddress>(subject), generation});
    require(observed.error.code == observer::Status::ok, "authenticated observer creation");
    auto lease = observed.owner.lease();
    instance = lease.generation();
    context = reinterpret_cast<std::uintptr_t>(native::detail::BootstrapContextAccess::state(lease));
    {
        auto first_snapshot = observer::observe(lease);
        auto second_snapshot = observer::observe(lease);
        require(first_snapshot.check().error.code == observer::Status::ok &&
            second_snapshot.check().error.code == observer::Status::ok, "two actual CNG observations");
        if (std::strcmp(mode, "bad-snapshot") == 0)
            const_cast<observer::Observation &>(second_snapshot.data()).measured.digest[31] ^= 1;
        auto changed = material;
        if (std::strcmp(mode, "bad-material") == 0) changed.back() ^= 1;
        const scoped::Spec first_spec{0x1020, 1, 7, 13, identity};
        const scoped::Spec second_spec{0x1020, 1, 7,
            std::strcmp(mode, "wrong-spec") == 0 ? 13u : 29u, identity};
        scoped::Scope first(parent_lease, first_spec, fold, material.data(), material.size(), std::move(first_snapshot));
        scoped::Scope second(parent_lease, second_spec, fold, changed.data(), changed.size(), std::move(second_snapshot));
        const std::pair<int, int> scenarios[] = {{-3, 14}, {0, 17}, {3, 10}};
        for (const auto &scenario : scenarios) {
            const int result = std::strcmp(mode, "swapped") == 0 ?
                multi_scope_edge_body(second, first, scenario.first) :
                multi_scope_edge_body(first, second, scenario.first);
            require(!negative && result == scenario.second,
                "an original edge did not preserve its selected result");
        }
        require(effects == 3 && admissions > 6 && first_admissions > 3 && second_admissions > 3,
            "both distinct Scope sources did not control generated edges");
    }
    binding.binding.reset(); parent_lease.reset(); parent.owner.close(); observed.owner.close(); lease.reset();
    require(FreeLibrary(module) != 0, "subject DLL unload");
    std::puts("two site-specific Scope sources, distinct CNG snapshots and normal cleanup pass");
}
