#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "contribution/scope.hpp"
#include "context/runtime.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "reference_slots.hpp"

#include <cstdio>
#include <cstring>

namespace native = pyobfuscator::native;
namespace scoped = native::contribution::scoped;
namespace observer = native::measurement::observer;
namespace reserved = native::measurement::reserved;
namespace {
std::uint64_t generation = 0;
const native::BootstrapContextLease *origin = nullptr;
native::BootstrapContextResult dispatch(const native::BootstrapContextRequest &request, void *) noexcept {
    if (request.operation_id != 0x1020 || request.input_size != sizeof(scoped::Admission) || request.input == nullptr)
        return {native::BootstrapContextStatus::invalid_request, 0};
    scoped::Admission message; std::memcpy(&message, request.input, sizeof(message));
    if (message.version != scoped::admission_version || message.size != sizeof(message) || message.routing != 0x1020 ||
            message.domain != 1 || message.source != 13 || message.generation != generation ||
            message.observation_owner != message.function || message.reserved != 0 || origin == nullptr ||
            message.observation_instance != origin->generation() ||
            message.observation_context != reinterpret_cast<std::uintptr_t>(native::detail::BootstrapContextAccess::state(*origin)))
        return {native::BootstrapContextStatus::context_mismatch, 0};
    for (unsigned index = 0; index != reserved::count; ++index)
        if (reserved::material_offsets[index] && reserved::identities[index].owner == message.function)
            return {native::BootstrapContextStatus::ok, generation};
    return {native::BootstrapContextStatus::unavailable, 0};
}
}
extern "C" __declspec(dllexport) int scope_slot_anchor(int value) { return value * 7 + 3; }

int main(int argc, char **argv) {
    if (argc != 4 || std::strcmp(argv[3], "1") != 0) return 1;
    native::path_fold::Storage fold{};
    std::uint32_t expected[reserved::count]{};
    auto *file = std::fopen(argv[1], "rb");
    if (!file) return 2;
    const bool read = std::fread(&fold, sizeof(fold), 1, file) == 1 &&
        std::fread(expected, sizeof(expected), 1, file) == 1;
    const int extra = std::fgetc(file), closed = std::fclose(file);
    if (!read || extra != EOF || closed) return 3;
    auto module = LoadLibraryA(argv[2]);
    if (!module) return 4;
    auto target = reinterpret_cast<native::platform::CodeAddress>(GetProcAddress(module, "measurement_target"));
    if (!target) return 5;
    const auto self = reinterpret_cast<native::platform::CodeAddress>(&scope_slot_anchor);
    auto parent = native::create_bootstrap_context({native::bootstrap_context_abi_version, dispatch, nullptr, nullptr});
    generation = parent.owner.generation();
    auto expected_parent = parent.owner.lease();
    auto publication = native::bind_bootstrap_context(expected_parent);
    if (parent.status != native::BootstrapContextStatus::ok || publication.status != native::BootstrapContextStatus::ok) return 6;
    for (unsigned index = 0; index != reserved::count; ++index) {
        const auto &identity = reserved::identities[index];
        auto owner = observer::create(reserved::data + reserved::offsets[index], identity.capacity, identity, fold.words,
            {{observer::Mode::per_use, 1000000000, 1000000000}, index == 0 ? self : target, generation});
        if (owner.error.code != observer::Status::ok) {
            std::fprintf(stderr, "reference failure at %u\n", index); return 7;
        }
        auto lease = owner.owner.lease();
        if (reserved::material_offsets[index]) {
            origin = &lease;
            scoped::Scope operation(expected_parent, {0x1020, 1, identity.owner, 13, identity}, fold,
                reserved::data + reserved::material_offsets[index], reserved::material_size, observer::observe(lease));
            const auto result = operation.query(0x1020, {1, identity.owner, 11, 13, 0});
            if (result.status != native::BootstrapContextStatus::ok || result.word != expected[index]) {
                std::fprintf(stderr, "material failure at %u auth%u word%u\n", index,
                    static_cast<unsigned>(result.authentication), result.word); return 8;
            }
        } else if (observer::observe(lease).check().error.code != observer::Status::ok) return 9;
    }
    publication.binding.reset(); parent.owner.close();
    if (!FreeLibrary(module)) return 10;
    std::puts("reserved scoped materials authenticate actual per-owner self/external code and derive independent expected words");
    return 0;
}
