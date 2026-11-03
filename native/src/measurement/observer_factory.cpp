#include "observer_internal.hpp"
#include "internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <new>
#include <utility>

namespace pyobfuscator::native::detail {
PYOBF_NATIVE_CFF_SDK BootstrapContextState *BootstrapContextAccess::state(const BootstrapContextLease &lease) noexcept {
    return lease.context_;
}
}
namespace pyobfuscator::native::measurement::observer {
namespace detail {
PYOBF_NATIVE_CFF_SDK void destroy(void *opaque) noexcept {
    auto *state = static_cast<State *>(opaque);
    auto view = state->view; state->view = {};
    auto reader_code = state->reader_code, codec_code = state->codec_code;
    state->reader_code = {}; state->codec_code = {};
    state->~State();
    PYOBF_NATIVE_ERASE(state, sizeof(State)); PYOBF_NATIVE_RELEASE(state);
    if (!PYOBF_NATIVE_CLOSE_CODE_VIEW(view)) PYOBF_NATIVE_PROTECTION_FAILURE(0x703);
    const auto reader_released = reader_code.module == nullptr || PYOBF_NATIVE_RELEASE_CODE(reader_code);
    const auto codec_released = codec_code.module == nullptr || PYOBF_NATIVE_RELEASE_CODE(codec_code);
    if (!reader_released || !codec_released) PYOBF_NATIVE_PROTECTION_FAILURE(0x704);
}
}
PYOBF_NATIVE_CFF_SDK Creation create(const std::uint8_t *package, std::size_t size,
        const reference::Identity &identity, const std::uint32_t (&words)[8], const Spec &spec) noexcept {
    const auto expected = identity; auto config = spec;
    const auto reader = config.reader == nullptr ? ReaderBinding{} : *config.reader;
    if (config.reader != nullptr && (reader.version != 1 || reader.owner != expected.owner || reader.owner == 0 ||
            reader.key == 0 || reader.capture == nullptr || reader.cache_codec == nullptr))
        return {{Status::invalid_specification}, {}};
    config.reader = nullptr;
    if (!detail::valid_policy(config.policy) || config.member == nullptr || config.subject_instance == 0)
        return {{Status::invalid_specification}, {}};
    auto decoded = reference::open(package, size, expected, words);
    if (decoded.status() != reference::Status::ok)
        return {{Status::reference_failed, BootstrapContextStatus::unavailable, decoded.status()}, {}};
    ModuleView view{};
    auto captured = PYOBF_NATIVE_OPEN_CODE_VIEW(config.member, view);
    std::size_t material_size = 0;
    if (captured == measurement::Status::ok)
        captured = measurement::detail::validate(decoded.descriptor(), &view, material_size);
    if (captured != measurement::Status::ok) {
        if (!PYOBF_NATIVE_CLOSE_CODE_VIEW(view)) PYOBF_NATIVE_PROTECTION_FAILURE(0x703);
        return {{Status::capture_failed, BootstrapContextStatus::unavailable, reference::Status::ok, captured}, {}};
    }
    auto *memory = PYOBF_NATIVE_ALLOCATE(sizeof(detail::State));
    if (memory == nullptr) {
        if (!PYOBF_NATIVE_CLOSE_CODE_VIEW(view)) PYOBF_NATIVE_PROTECTION_FAILURE(0x703);
        return {{Status::allocation_failed}, {}};
    }
    auto *state = new (memory) detail::State{std::move(decoded), expected, config, view};
    state->reader = reader;
    if (reader.owner != 0) {
        state->reader_code = PYOBF_NATIVE_RETAIN_CODE(reinterpret_cast<platform::CodeAddress>(reader.capture));
        state->codec_code = PYOBF_NATIVE_RETAIN_CODE(reinterpret_cast<platform::CodeAddress>(reader.cache_codec));
        if (state->reader_code.module == nullptr || state->codec_code.module == nullptr) {
            detail::destroy(state); return {{Status::invalid_specification}, {}};
        }
    }
    auto created = create_bootstrap_context({bootstrap_context_abi_version, detail::dispatch, state, detail::destroy});
    if (created.status != BootstrapContextStatus::ok) {
        detail::destroy(state); return {detail::context_error(created.status), {}};
    }
    auto lease = created.owner.lease();
    if (lease.availability() != BootstrapContextStatus::ok)
        return {detail::context_error(lease.availability()), {}};
    state->context = pyobfuscator::native::detail::BootstrapContextAccess::state(lease);
    return {detail::good, std::move(created.owner)};
}
}  // namespace pyobfuscator::native::measurement::observer
