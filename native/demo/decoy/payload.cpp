#include "handoff.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

extern "C" int pyobf_demo_decoy_compute(int);

extern "C" __declspec(dllexport) PYOBF_NATIVE_CFF int pyobf_native_inner_entry(
    const pyobfuscator::native::demo::DecoyHandoff *handoff, int value) {
    using namespace pyobfuscator::native::demo;
    if (handoff == nullptr || handoff->abi_version != decoy_handoff_version ||
            handoff->size != sizeof(DecoyHandoff) || handoff->role != decoy_role)
        return -110;
    if (handoff->failure != -2 && handoff->failure != -4 && handoff->failure != -7 && handoff->failure != -8)
        return -111;
    return pyobf_demo_decoy_compute(value);
}
