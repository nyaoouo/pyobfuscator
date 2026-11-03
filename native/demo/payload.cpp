#include "demo_config.hpp"
#include "bootstrap/handoff.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/sdk.hpp"
#ifndef PYOBF_DEMO_PAYLOAD_BOUND
#define PYOBF_DEMO_PAYLOAD_BOUND 0
#endif
#if PYOBF_DEMO_PAYLOAD_BOUND
#include "pyobfuscator_native/contribution_marker.hpp"
#endif
#if defined(PYOBF_DEMO_POST_CODE_HASH)
#include "post_payload.hpp"
#endif

#ifdef PYOBF_DEMO_HAS_ASSET
#include "assets/asset_sample.hpp"

extern "C" __declspec(dllexport) PYOBF_NATIVE_CFF int pyobf_demo_asset_read(unsigned index) {
    const auto view = pyobfuscator::native::assets::get_sample();
    if (index >= view.size) return -1;
    return view.data[index];
}
#endif

#if PYOBF_DEMO_PAYLOAD_BOUND && !defined(PYOBF_DEMO_POST_CODE_HASH)
extern "C" {
// Keep the private compiler owner stable across C++ ABI mangling.
static int pyobf_demo_bound_compute(const pyobfuscator::native::BootstrapContextLease &, int)
    __asm__("pyobf_demo_bound_compute");
static PYOBF_NATIVE_CFF int pyobf_demo_bound_compute(
    const pyobfuscator::native::BootstrapContextLease &expected, int value) {
    pyobf_native_contribution_site_v1(expected, 701);
#elif !PYOBF_DEMO_PAYLOAD_BOUND
extern "C" __declspec(dllexport) PYOBF_NATIVE_CFF int pyobf_demo_compute(int value) {
#endif
#if !PYOBF_DEMO_PAYLOAD_BOUND || !defined(PYOBF_DEMO_POST_CODE_HASH)
    int result = 0;
    if (value < 0) {
        result = -value + 11;
    } else if (value == 0) {
        result = 17;
    } else {
        result = value * 3 + 1;
    }
    return result;
}
#endif

#if PYOBF_DEMO_PAYLOAD_BOUND && !defined(PYOBF_DEMO_POST_CODE_HASH)
}  // extern "C"
#endif
#if PYOBF_DEMO_PAYLOAD_BOUND
extern "C" __declspec(dllexport) PYOBF_NATIVE_CFF int pyobf_demo_compute(int) {
    return -103;
}
#endif

extern "C" __declspec(dllexport) PYOBF_NATIVE_CFF int pyobf_native_inner_entry(
    const pyobfuscator::native::demo::PayloadHandoff *handoff, int value) {
    using namespace pyobfuscator::native;
    using namespace pyobfuscator::native::demo;
    if (handoff == nullptr || handoff->abi_version != handoff_abi_version || handoff->expected == nullptr ||
            handoff->publication == nullptr || handoff->record_stage == nullptr ||
            handoff->routing_tag != PYOBF_DEMO_ENV_OPERATION_ID || handoff->generation == 0 ||
            handoff->expected->generation() != handoff->generation || handoff->publication->binding.generation() != 0)
        return -100;
    *handoff->publication = bind_bootstrap_context(*handoff->expected);
    if (handoff->publication->status != BootstrapContextStatus::ok) return -100;
    handoff->record_stage(4, handoff->observer_context);
    const LifecycleMessage message{handoff->generation, handoff->routing_tag, LifecycleOperation::enter_payload};
    const auto admission = call_bound_bootstrap(*handoff->expected, {message.routing_tag, &message, sizeof(message)});
    if (admission.status == BootstrapContextStatus::ok) handoff->record_stage(5, handoff->observer_context);
    int result;
    if (admission.status != BootstrapContextStatus::ok || admission.value > 1) {
        result = -101;
    } else if (pyobfuscator::native::inspect_current_process().status !=
               pyobfuscator::native::DetectionStatus::unavailable) {
        result = -102;
    } else {
#if defined(PYOBF_DEMO_POST_CODE_HASH)
        result = pyobf_demo_post_payload(handoff, value);
#elif PYOBF_DEMO_PAYLOAD_BOUND
        result = pyobf_demo_bound_compute(*handoff->expected, value);
#else
        result = pyobf_demo_compute(value);
#endif
    }
    return result;
}
