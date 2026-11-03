#include "observer_internal.hpp"
#include "capture.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::observer::detail {
PYOBF_NATIVE_CFF_SDK void sample(State &state, std::uint64_t epoch, std::uint64_t sequence, Response &output) noexcept {
    // No context gate is held across mapped reads, CNG, allocation or their cleanup.
    auto captured = state.reader.owner == 0 ? measurement::capture(state.reference.descriptor(), state.spec.member) :
        state.reader.capture(state.reference.descriptor(), state.spec.member, state.reader.key);
    lock(state);
    auto record = header(state, sequence); record.epoch = epoch; record.measured = captured.data();
    auto error = live(state);
    if (error.code == Status::ok && epoch != state.epoch) error.code = Status::revoked;
    if (error.code == Status::ok && record.measured.status != measurement::Status::ok) {
        error.code = Status::capture_failed; error.capture = record.measured.status;
    }
    ClockSample now{};
    if (error.code == Status::ok) {
        if (!clock(now)) { error.code = Status::clock_failed; error.capture = measurement::Status::clock_failed; }
        else error = inspect(state, record, now);
    }
    if (error.code != Status::ok) {
        if (!state.context->closing) revoke(state, error);
        record.error = error; fill(state, record, false, output); unlock(state); return;
    }
    if (!state.has_cache || sequence > state.published) {
        auto cached = record;
        if (state.reader.owner != 0 && !state.reader.cache_codec(state.reader.key, cached)) {
            record.error.code = Status::invalid_snapshot; revoke(state, record.error);
            fill(state, record, false, output); unlock(state); return;
        }
        state.cached = cached; state.has_cache = true; state.published = sequence;
    }
    fill(state, record, false, output); unlock(state);
}
PYOBF_NATIVE_CFF_SDK void acquire(State &state, bool force, Response &output) noexcept {
    lock(state);
    auto error = live(state);
    if (error.code == Status::ok && state.has_cache && !force && state.spec.policy.mode != Mode::per_use) {
        auto cached = state.cached;
        ClockSample now{};
        if (state.reader.owner != 0 && !state.reader.cache_codec(state.reader.key, cached)) error.code = Status::invalid_snapshot;
        else if (!clock(now)) { error.code = Status::clock_failed; error.capture = measurement::Status::clock_failed; }
        else error = inspect(state, cached, now);
        if (error.code == Status::ok) { fill(state, cached, true, output); unlock(state); return; }
        if (error.code == Status::expired) error = good;
        else revoke(state, error);
    }
    if (error.code == Status::ok && state.admitted == UINT64_MAX) {
        error.code = Status::generation_exhausted; revoke(state, error);
    }
    if (error.code != Status::ok) {
        output.data = header(state, 0); output.data.error = error; unlock(state); return;
    }
    const auto sequence = ++state.admitted, epoch = state.epoch;
    unlock(state);
    sample(state, epoch, sequence, output);
}
PYOBF_NATIVE_CFF_SDK void validate(State &state, const Observation &record, Validation &output) noexcept {
    lock(state);
    auto error = live(state);
    ClockSample now{};
    if (error.code == Status::ok) {
        if (!clock(now)) { error.code = Status::clock_failed; error.capture = measurement::Status::clock_failed; }
        else error = inspect(state, record, now);
        if (error.code != Status::ok && error.code != Status::expired) revoke(state, error);
    }
    output = {error, now.ticks, now.frequency};
    unlock(state);
}
}  // namespace pyobfuscator::native::measurement::observer::detail
