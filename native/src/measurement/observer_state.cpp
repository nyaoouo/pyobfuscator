#include "observer_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::observer::detail {
PYOBF_NATIVE_CFF_SDK bool same_identity(const reference::Identity &a, const reference::Identity &b) noexcept {
    for (unsigned index = 0; index != 16; ++index)
        if (a.build[index] != b.build[index] || a.image[index] != b.image[index]) return false;
    return a.owner == b.owner && a.subject == b.subject && a.kind == b.kind &&
        a.stage == b.stage && a.capacity == b.capacity;
}
PYOBF_NATIVE_CFF_SDK Error context_error(BootstrapContextStatus status) noexcept {
    return {status == BootstrapContextStatus::closed ? Status::closed : Status::context_failed, status};
}
PYOBF_NATIVE_CFF_SDK void lock(State &state) noexcept {
    pyobfuscator::native::detail::context_lock(state.context->gate);
}
PYOBF_NATIVE_CFF_SDK void unlock(State &state) noexcept {
    pyobfuscator::native::detail::context_unlock(state.context->gate);
}
PYOBF_NATIVE_CFF_SDK Error live(const State &state) noexcept {
    return state.context->closing ? context_error(BootstrapContextStatus::closed) : state.failure;
}
PYOBF_NATIVE_CFF_SDK void revoke(State &state, Error error) noexcept {
    if (state.failure.code != Status::ok) return;
    if (state.epoch == UINT64_MAX) error.code = Status::generation_exhausted;
    else ++state.epoch;
    state.failure = error;
    state.cached = {}; state.has_cache = false;
}
PYOBF_NATIVE_CFF_SDK Observation header(const State &state, std::uint64_t sequence) noexcept {
    return {state.identity, state.spec.policy, state.context->generation, state.spec.subject_instance,
        state.epoch, sequence, {}, good};
}
PYOBF_NATIVE_CFF_SDK bool clock(ClockSample &sample) noexcept {
    sample = {};
    if (!PYOBF_NATIVE_MEASUREMENT_CLOCK(sample) || sample.frequency == 0) { sample = {}; return false; }
    return true;
}
PYOBF_NATIVE_CFF_SDK Error inspect(const State &state, const Observation &record, const ClockSample &now) noexcept {
    auto error = good;
    if (!same_identity(record.identity, state.identity) || record.instance != state.context->generation ||
            record.subject_instance != state.spec.subject_instance ||
            record.sequence == 0 || record.sequence > state.admitted ||
            record.policy.mode != state.spec.policy.mode || record.policy.max_age_ns != state.spec.policy.max_age_ns ||
            record.policy.max_scan_ns != state.spec.policy.max_scan_ns || record.error.code != Status::ok ||
            record.measured.status != measurement::Status::ok || record.measured.kind != state.identity.kind ||
            record.measured.subject != state.identity.subject || record.measured.owner != state.identity.owner) {
        error.code = Status::invalid_snapshot; return error;
    }
    if (record.epoch != state.epoch) { error.code = Status::revoked; return error; }
    unsigned difference = 0;
    for (unsigned index = 0; index != 32; ++index)
        difference |= record.measured.digest[index] ^ state.reference.expected_digest()[index];
    if (difference != 0) { error.code = Status::digest_mismatch; return error; }
    error.code = interval(record.measured, state.spec.policy, now);
    return error;
}
PYOBF_NATIVE_CFF_SDK void fill(const State &state, const Observation &record, bool reused, Response &output) noexcept {
    output.data = record; output.reused = reused;
    for (unsigned index = 0; index != 32; ++index) output.expected[index] = state.reference.expected_digest()[index];
}
}  // namespace pyobfuscator::native::measurement::observer::detail
