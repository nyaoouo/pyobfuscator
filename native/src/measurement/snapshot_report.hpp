#pragma once

#include "observer.hpp"

namespace pyobfuscator::native::measurement::observer {

// A value-only record of one pending observation and its validation at copy time.
// The caller retains the Snapshot for any later authorization decision.
struct SnapshotReport {
    Observation observation{};
    Validation validation{};
    bool reused = false;
};

Status copy_snapshot_report(const Snapshot &snapshot, SnapshotReport &output) noexcept;

}  // namespace pyobfuscator::native::measurement::observer
