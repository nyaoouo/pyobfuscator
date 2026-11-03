#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "bootstrap/handoff.hpp"
#include "contribution/protocol.hpp"
#include "demo_config.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <initializer_list>

namespace {
using namespace pyobfuscator::native;
using namespace pyobfuscator::native::demo;
struct Probe {
    bool unavailable;
    unsigned queries = 0;
    bool valid = false;
    std::uint32_t private_words[8]{};
};
void borrowed_destroy(void *) noexcept {}

BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *opaque) noexcept {
    auto &probe = *static_cast<Probe *>(opaque);
    if (request.operation_id != PYOBF_DEMO_ENV_OPERATION_ID) return {BootstrapContextStatus::invalid_request, 0};
    if (request.input_size == sizeof(LifecycleMessage)) return {BootstrapContextStatus::ok, 1};
    if (request.input_size != sizeof(contribution::Message)) return {BootstrapContextStatus::invalid_request, 0};
    if (probe.queries++ == 0) { std::puts("source-request"); std::fflush(stdout); }
    if (probe.unavailable) return {BootstrapContextStatus::unavailable, 0};
    if (probe.valid) {
        const auto &message = *static_cast<const contribution::Message *>(request.input);
        if (message.version != contribution::context_protocol_version ||
                message.size != sizeof(message)) return {BootstrapContextStatus::invalid_request, 0};
        const auto result = contribution::derive(probe.private_words, message.routing_tag, message.point);
        if (result.status != BootstrapContextStatus::ok) return {result.status, 0};
        return {BootstrapContextStatus::ok,
            (std::uint64_t(contribution::context_reply_tag) << 32) | result.word};
    }
    return {BootstrapContextStatus::ok, (std::uint64_t(contribution::context_reply_tag) << 32) | 1};
}

void observe(std::uint32_t stage, void *) {
    if (stage == 5) { std::puts("legacy-admitted"); std::fflush(stdout); }
}
int reference(int value) { return value < 0 ? -value + 11 : value == 0 ? 17 : value * 3 + 1; }
}

int main(int argc, char **argv) {
    if (argc != 4 && argc != 5) return 1;
    const bool valid = std::strcmp(argv[3], "valid") == 0;
    if (valid != (argc == 5)) return 1;
    const bool strict = std::strcmp(argv[2], "strict") == 0 || std::strcmp(argv[2], "measured") == 0;
    const auto image = LoadLibraryA(argv[1]);
    if (image == nullptr) return 2;
    const auto entry = reinterpret_cast<InnerEntry>(GetProcAddress(image, "pyobf_native_inner_entry"));
    const auto compute = reinterpret_cast<int (*)(int)>(GetProcAddress(image, "pyobf_demo_compute"));
    if (entry == nullptr || compute == nullptr) return 3;
    if (std::strcmp(argv[3], "detached") == 0) {
        if (strict && GetProcAddress(image, "pyobf_demo_bound_compute") != nullptr) return 4;
        if (entry(nullptr, 5) != -100 || compute(5) != (strict ? -103 : reference(5))) return 4;
        if (!FreeLibrary(image)) return 5;
        std::puts("detached-profile-verified");
        return 0;
    }
    Probe probe{std::strcmp(argv[3], "unavailable") == 0};
    if (valid) {
        auto *file = std::fopen(argv[4], "rb");
        if (file == nullptr) return 9;
        const auto read = std::fread(probe.private_words, 1, sizeof(probe.private_words), file);
        const bool exact = read == sizeof(probe.private_words) && std::fgetc(file) == EOF;
        std::fclose(file);
        if (!exact) return 9;
        probe.valid = true;
    }
    auto created = create_bootstrap_context({bootstrap_context_abi_version, dispatch, &probe, borrowed_destroy});
    if (created.status != BootstrapContextStatus::ok) return 6;
    auto expected = created.owner.lease();
    BootstrapContextBindingCreation publication{};
    const PayloadHandoff handoff{handoff_abi_version, PYOBF_DEMO_ENV_OPERATION_ID, expected.generation(),
        &expected, &publication, observe, nullptr};
    bool completed = true;
    for (int value : {-7, 0, 5, 11}) {
        completed &= entry(&handoff, value) == reference(value);
        publication.binding.reset();
    }
    created.owner.close();
    if (!created.owner.quiescent()) return 7;
    publication.binding.reset();
    expected.reset();
    created.owner = {};
    if (!FreeLibrary(image)) return 8;
    std::puts(completed ? "payload-completed" : "payload-refused");
    return 0;
}
