#include "sdk_internal.hpp"
#include "pyobfuscator_native/bootstrap_api.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/sdk.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native {

namespace {
platform::AtomicWord32 api_gate{0};
BootstrapApi bound_api{};
}

PYOBF_NATIVE_CFF_SDK bool bind_bootstrap_api(const BootstrapApi *api) noexcept {
    if (api == nullptr || api->abi_version != bootstrap_abi_version || api->call == nullptr ||
        api->record_stage == nullptr) {
        return false;
    }
    while (PYOBF_NATIVE_ATOMIC_CAS32(&api_gate, 0, 1) != 0) PYOBF_NATIVE_SPIN_PAUSE();
    bound_api = *api;
    PYOBF_NATIVE_ATOMIC_STORE32(&api_gate, 0);
    return true;
}

PYOBF_NATIVE_CFF_SDK void unbind_bootstrap_api() noexcept {
    while (PYOBF_NATIVE_ATOMIC_CAS32(&api_gate, 0, 1) != 0) PYOBF_NATIVE_SPIN_PAUSE();
    bound_api = {};
    PYOBF_NATIVE_ATOMIC_STORE32(&api_gate, 0);
}

PYOBF_NATIVE_CFF_SDK int call_bootstrap(std::uint32_t operation_id) noexcept {
    while (PYOBF_NATIVE_ATOMIC_CAS32(&api_gate, 0, 1) != 0) PYOBF_NATIVE_SPIN_PAUSE();
    const auto api = bound_api;
    PYOBF_NATIVE_ATOMIC_STORE32(&api_gate, 0);
    return api.call == nullptr ? -1 : api.call(operation_id, api.context);
}

PYOBF_NATIVE_CFF_SDK DetectionReport inspect_current_process(
    DetectionCallback callback, void *user_data) {
    DetectionReport report{DetectionStatus::unavailable};
    switch (detail::inspect_current_process()) {
    case detail::DetectionState::unavailable:
        break;
    case detail::DetectionState::clear:
        report.status = DetectionStatus::clear;
        break;
    case detail::DetectionState::triggered:
        report.status = DetectionStatus::detected;
        break;
    }
    if (callback != nullptr) {
        callback(report, user_data);
    }
    return report;
}

}  // namespace pyobfuscator::native
