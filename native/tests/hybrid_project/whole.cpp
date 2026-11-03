#include "api.hpp"
#include "asset_sample.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/sdk.hpp"

namespace {
PYOBF_NATIVE_CFF void record_report(const pyobfuscator::native::DetectionReport &report, void *context) {
    *static_cast<int *>(context) = report.status == pyobfuscator::native::DetectionStatus::unavailable ? 1 : 0;
}
}

extern "C" HYBRID_SUBJECT_API PYOBF_NATIVE_CFF int whole_callback_result(int value) {
    int observed = 0;
    const auto report = pyobfuscator::native::inspect_current_process(record_report, &observed);
    const auto asset = pyobfuscator::native::assets::get_sample();
    if (report.status != pyobfuscator::native::DetectionStatus::unavailable || observed != 1 || asset.size == 0) return -10000;
    return value + asset.data[0] + 7;
}
