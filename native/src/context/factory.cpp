#include "runtime.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <new>

namespace pyobfuscator::native {

PYOBF_NATIVE_CFF_SDK BootstrapContextCreation create_bootstrap_context(const BootstrapContextSpec &spec) noexcept {
    if (spec.abi_version != bootstrap_context_abi_version || spec.dispatch == nullptr ||
        (spec.user_data != nullptr && spec.destroy == nullptr))
        return {BootstrapContextStatus::invalid_specification, {}};
    void *memory = PYOBF_NATIVE_ALLOCATE(sizeof(detail::BootstrapContextState));
    if (memory == nullptr) return {BootstrapContextStatus::allocation_failed, {}};
    const auto dispatch_provider = PYOBF_NATIVE_RETAIN_CODE(reinterpret_cast<platform::CodeAddress>(spec.dispatch));
    platform::CodeLease destroy_provider{};
    if (dispatch_provider.module != nullptr && spec.destroy != nullptr)
        destroy_provider = PYOBF_NATIVE_RETAIN_CODE(reinterpret_cast<platform::CodeAddress>(spec.destroy));
    auto status = BootstrapContextStatus::code_unavailable;
    std::uint64_t generation = 0;
    if (dispatch_provider.module != nullptr && (spec.destroy == nullptr || destroy_provider.module != nullptr)) {
        generation = detail::next_context_generation();
        status = generation == 0 ? BootstrapContextStatus::generation_exhausted : BootstrapContextStatus::ok;
    }
    if (status != BootstrapContextStatus::ok) {
        const bool destroy_released = PYOBF_NATIVE_RELEASE_CODE(destroy_provider);
        const bool dispatch_released = PYOBF_NATIVE_RELEASE_CODE(dispatch_provider);
        if (!destroy_released || !dispatch_released)
            PYOBF_NATIVE_PROTECTION_FAILURE(0x203);
        PYOBF_NATIVE_ERASE(memory, sizeof(detail::BootstrapContextState));
        PYOBF_NATIVE_RELEASE(memory);
        return {status, {}};
    }
    // Initialize array members explicitly: MSVC rejects copying these const aggregates here.
    auto *context = new (memory) detail::BootstrapContextState{
        spec, generation, {{dispatch_provider.module}, {destroy_provider.module}}};
    return {BootstrapContextStatus::ok, BootstrapContextOwner(context)};
}

}  // namespace pyobfuscator::native
