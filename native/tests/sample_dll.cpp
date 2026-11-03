#include "pyobfuscator_native/sdk.hpp"

namespace {

void record_detection(const pyobfuscator::native::DetectionReport &report, void *user_data) {
    auto *count = static_cast<int *>(user_data);
    if (report.status == pyobfuscator::native::DetectionStatus::unavailable) {
        ++*count;
    }
}

}  // namespace

extern "C" __declspec(dllexport) int pyobf_native_sample_probe() {
    int callback_count = 0;
    const auto report = pyobfuscator::native::inspect_current_process(
        record_detection, &callback_count);
    return report.status == pyobfuscator::native::DetectionStatus::unavailable &&
                   callback_count == 1
               ? 7
               : -1;
}
