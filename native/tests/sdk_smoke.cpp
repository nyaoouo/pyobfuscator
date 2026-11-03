#include "pyobfuscator_native/bootstrap_api.hpp"
#include "pyobfuscator_native/sdk.hpp"

namespace {

void record_detection(const pyobfuscator::native::DetectionReport &report, void *user_data) {
    auto *count = static_cast<int *>(user_data);
    if (report.status == pyobfuscator::native::DetectionStatus::unavailable) {
        ++*count;
    }
}

int dispatch(std::uint32_t operation_id, void *user_data) noexcept {
    auto *count = static_cast<int *>(user_data);
    ++*count;
    return operation_id == 7 ? 11 : -1;
}

void record_stage(std::uint32_t, void *) {}

}  // namespace

int main() {
    int callback_count = 0;
    const auto report = pyobfuscator::native::inspect_current_process(
        record_detection, &callback_count);
    const auto no_callback = pyobfuscator::native::inspect_current_process();
    int dispatch_count = 0;
    const pyobfuscator::native::BootstrapApi invalid{
        0, dispatch, record_stage, &dispatch_count};
    const pyobfuscator::native::BootstrapApi valid{
        pyobfuscator::native::bootstrap_abi_version, dispatch, record_stage, &dispatch_count};
    const bool invalid_rejected = !pyobfuscator::native::bind_bootstrap_api(&invalid) &&
                                  pyobfuscator::native::call_bootstrap(7) == -1;
    const bool bound = pyobfuscator::native::bind_bootstrap_api(&valid) &&
                       pyobfuscator::native::call_bootstrap(7) == 11 &&
                       pyobfuscator::native::call_bootstrap(8) == -1;
    pyobfuscator::native::unbind_bootstrap_api();
    const bool unbound = pyobfuscator::native::call_bootstrap(7) == -1;
    // A framework build must not report a clean environment before detectors exist.
    return report.status == pyobfuscator::native::DetectionStatus::unavailable &&
                   no_callback.status == pyobfuscator::native::DetectionStatus::unavailable &&
                   callback_count == 1 && invalid_rejected && bound && unbound &&
                   dispatch_count == 2
               ? 0
               : 1;
}
