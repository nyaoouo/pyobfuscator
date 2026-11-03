#include "snapshot_report.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::observer {

PYOBF_NATIVE_CFF_SDK Status copy_snapshot_report(const Snapshot &snapshot, SnapshotReport &output) noexcept {
    // Copy the frozen observation before checking: a failed validation still reports
    // the original measured value and its precise failure source.
    SnapshotReport result{snapshot.data(), snapshot.check(), snapshot.reused()};
    output = result;
    return result.validation.error.code;
}

}  // namespace pyobfuscator::native::measurement::observer
