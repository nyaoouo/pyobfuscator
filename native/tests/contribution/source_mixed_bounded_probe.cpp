#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "context/runtime.hpp"
#include "contribution/protocol.hpp"
#include "contribution/scope.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "bounded_labels.hpp"

#include <cstdio>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

namespace native = pyobfuscator::native;
namespace contribution = native::contribution;
namespace scoped = contribution::scoped;
namespace observer = native::measurement::observer;
extern "C" int mixed_bounded_body(native::BootstrapContextLease &, scoped::Scope &, int) noexcept(false);

namespace {
constexpr std::uint32_t private_words[8]{0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
std::uint64_t generation = 0, instance = 0;
std::uintptr_t context = 0;
unsigned owned_queries = 0, admissions = 0, effects = 0;
std::uint32_t seen_sites = 0, denied_site = 0;
bool negative = false;
void require(bool condition, const char *reason) {
    if (!condition) { std::fprintf(stderr, "mixed site: %s\n", reason); std::exit(1); }
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
    if (request.operation_id != 0x1020 || request.input == nullptr)
        return {native::BootstrapContextStatus::invalid_request, 0};
    if (request.input_size == sizeof(contribution::Message)) {
        contribution::Message message{};
        std::memcpy(&message, request.input, sizeof(message));
        bool source = false;
        for (unsigned index = 0; index < bounded_site_count; ++index)
            if (message.point.site == bounded_site_labels[index] &&
                    message.point.source == bounded_source_words[index]) {
                source = true;
                seen_sites |= 1u << index;
            }
        if (message.version != contribution::context_protocol_version || message.size != sizeof(message) ||
                message.routing_tag != 0x1020 || message.reserved != 0 || message.tail_reserved != 0 ||
                message.generation != generation || message.point.domain != 1 || message.point.function != 7 ||
                !source)
            return {native::BootstrapContextStatus::context_mismatch, 0};
        if (message.point.site == denied_site) {
            std::fprintf(stderr, "denied-site:%u\n", denied_site);
            return {native::BootstrapContextStatus::context_mismatch, 0};
        }
        const auto result = contribution::derive(private_words, message.routing_tag, message.point);
        if (result.status != native::BootstrapContextStatus::ok) return {result.status, 0};
        ++owned_queries;
        return {native::BootstrapContextStatus::ok,
            (std::uint64_t(contribution::context_reply_tag) << 32) | result.word};
    }
    if (request.input_size == sizeof(scoped::Admission)) {
        scoped::Admission message{};
        std::memcpy(&message, request.input, sizeof(message));
        if (message.version != scoped::admission_version || message.size != sizeof(message) || message.reserved != 0 ||
                message.routing != 0x1020 || message.domain != 1 || message.function != 7 || message.source != 29 ||
                message.observation_owner != 7 || message.generation != generation ||
                message.observation_instance != instance || message.observation_context != context)
            return {native::BootstrapContextStatus::context_mismatch, 0};
        ++admissions;
        return {native::BootstrapContextStatus::ok, generation};
    }
    return {native::BootstrapContextStatus::invalid_request, 0};
}
}

extern "C" int bounded_effect(native::BootstrapContextLease &owned, scoped::Scope &measured,
        int result) noexcept(false) {
    ++effects;
    if (negative) std::exit(91);
    require(owned.generation() == generation && measured.observation().sequence != 0 &&
        measured.observation().identity.owner == 7 && owned_queries >= 1 && admissions >= 2,
        "distinct owned and measured providers did not feed the effect");
    return result;
}

extern "C" int bounded_wrapper_left(native::BootstrapContextLease &owned, scoped::Scope &measured, int result) noexcept(false) { return bounded_effect(owned, measured, result); }
extern "C" int bounded_wrapper_right(native::BootstrapContextLease &owned, scoped::Scope &measured, int result) noexcept(false) { return bounded_effect(owned, measured, result); }
extern "C" int bounded_compute_negative(native::BootstrapContextLease &owned, scoped::Scope &measured, int result) noexcept(false) { return bounded_effect(owned, measured, result); }
extern "C" int bounded_compute_zero(native::BootstrapContextLease &owned, scoped::Scope &measured, int result) noexcept(false) { return bounded_effect(owned, measured, result); }
extern "C" int bounded_compute_positive(native::BootstrapContextLease &owned, scoped::Scope &measured, int result) noexcept(false) { return bounded_effect(owned, measured, result); }

int main(int argc, char **argv) {
    require(argc == 5 || argc == 6 || argc == 7, "metadata/reference/material/DLL/provider inputs");
    const auto mode = argc >= 6 ? argv[5] : "normal";
    require(std::strcmp(mode, "normal") == 0 || std::strcmp(mode, "wrong-owned") == 0 ||
        std::strcmp(mode, "wrong-measured") == 0 || std::strcmp(mode, "bad-snapshot") == 0 ||
        std::strcmp(mode, "bad-material") == 0 || std::strcmp(mode, "same-generation-foreign") == 0 ||
        std::strcmp(mode, "empty-owned") == 0 || std::strcmp(mode, "closed-owned") == 0 ||
        std::strcmp(mode, "rebound-owned") == 0 || std::strcmp(mode, "deny-site") == 0,
        "unknown negative mode");
    negative = std::strcmp(mode, "normal") != 0 && std::strcmp(mode, "deny-site") != 0;
    if (std::strcmp(mode, "deny-site") == 0) {
        const char *label = std::getenv("PYOBF_TEST_BOUNDED_DENY_LABEL");
        require(label != nullptr, "missing denied site label");
        denied_site = static_cast<std::uint32_t>(std::strtoul(label, nullptr, 10));
    }
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
        auto snapshot = observer::observe(lease);
        require(snapshot.check().error.code == observer::Status::ok, "actual CNG observation");
        if (std::strcmp(mode, "bad-snapshot") == 0)
            const_cast<observer::Observation &>(snapshot.data()).measured.digest[31] ^= 1;
        auto changed = material;
        if (std::strcmp(mode, "bad-material") == 0) changed.back() ^= 1;
        const scoped::Spec spec{0x1020, 1, 7,
            std::strcmp(mode, "wrong-measured") == 0 ? 13u : 29u, identity};
        scoped::Scope scope(parent_lease, spec, fold, changed.data(), changed.size(), std::move(snapshot));
        native::BootstrapContextCreation second{};
        native::BootstrapContextCreation foreign{};
        native::BootstrapContextLease wrong;
        HMODULE foreign_module = nullptr;
        std::atomic<unsigned> foreign_destroyed{0};
        if (std::strcmp(mode, "same-generation-foreign") == 0) {
            require(argc == 7, "separate context factory path");
            foreign_module = LoadLibraryA(argv[6]); require(foreign_module != nullptr, "separate context factory load");
            using ForeignFactory = void (*)(std::atomic<unsigned> *, native::BootstrapContextCreation *) noexcept;
            const auto factory = reinterpret_cast<ForeignFactory>(GetProcAddress(foreign_module, "context_provider_owned"));
            require(factory != nullptr, "separate context factory export");
            factory(&foreign_destroyed, &foreign);
            require(foreign.status == native::BootstrapContextStatus::ok &&
                foreign.owner.generation() == generation &&
                native::detail::BootstrapContextAccess::state(foreign.owner.lease()) !=
                    native::detail::BootstrapContextAccess::state(parent_lease),
                "actual equal-generation foreign context");
            wrong = foreign.owner.lease();
        } else if (std::strcmp(mode, "wrong-owned") == 0 ||
                std::strcmp(mode, "closed-owned") == 0 ||
                std::strcmp(mode, "rebound-owned") == 0) {
            second = native::create_bootstrap_context({native::bootstrap_context_abi_version, dispatch, nullptr, nullptr});
            require(second.status == native::BootstrapContextStatus::ok, "wrong owner creation");
            wrong = second.owner.lease();
        }
        if (std::strcmp(mode, "closed-owned") == 0) second.owner.close();
        if (std::strcmp(mode, "rebound-owned") == 0) {
            binding.binding.reset();
            auto rebound = native::bind_bootstrap_context(wrong);
            require(rebound.status == native::BootstrapContextStatus::ok, "wrong owner rebind");
            binding = std::move(rebound);
        }
        native::BootstrapContextLease empty;
        auto &selected = std::strcmp(mode, "empty-owned") == 0 ? empty :
            (std::strcmp(mode, "wrong-owned") == 0 || std::strcmp(mode, "closed-owned") == 0 ||
                std::strcmp(mode, "same-generation-foreign") == 0) ? wrong : parent_lease;
        const char *value_text = std::getenv("PYOBF_TEST_BOUNDED_VALUE");
        require(value_text != nullptr && (std::strcmp(value_text, "-3") == 0 ||
            std::strcmp(value_text, "0") == 0 || std::strcmp(value_text, "3") == 0),
            "unknown bounded-edge test selection");
        const int value = std::atoi(value_text);
        const int result = mixed_bounded_body(selected, scope, value);
        const int expected = bounded_compute ? (value < 0 ? 11 : value == 0 ? 17 : 23) :
            (value < 0 ? 10 : 20);
        const std::uint32_t expected_sites = value < 0 ? bounded_expected_minus :
            value == 0 ? bounded_expected_zero : bounded_expected_plus;
        unsigned expected_queries = 0;
        for (auto bits = expected_sites; bits != 0; bits >>= 1) expected_queries += bits & 1u;
        const unsigned expected_effects = bounded_compute && bounded_optimized && value == 0 ? 0 :
            !bounded_compute && bounded_optimized && value >= 0 ? 0 : 1;
        require(!negative && denied_site == 0 && result == expected && effects == expected_effects &&
            seen_sites == expected_sites && owned_queries == expected_queries &&
            admissions >= expected_queries,
            "mixed site groups did not control the selected body path");
        wrong.reset(); second.owner.close(); foreign.owner.close();
        if (foreign_module != nullptr) require(FreeLibrary(foreign_module) != 0, "separate factory unload");
    }
    binding.binding.reset(); parent_lease.reset(); parent.owner.close(); observed.owner.close(); lease.reset();
    require(FreeLibrary(module) != 0, "subject DLL unload");
    std::puts("mixed owned-context and measured-Scope sites, actual CNG and cleanup pass");
}
