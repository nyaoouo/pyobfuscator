#pragma once

namespace pyobfuscator::native {

enum class DetectionStatus {
    unavailable,
    clear,
    detected,
};

struct DetectionReport {
    DetectionStatus status;
};

using DetectionCallback = void (*)(const DetectionReport &report, void *user_data);

// Only an integration seam for now. Every platform backend reports unavailable until
// detector behavior is implemented and validated.
DetectionReport inspect_current_process(DetectionCallback callback = nullptr,
                                        void *user_data = nullptr);

}  // namespace pyobfuscator::native
