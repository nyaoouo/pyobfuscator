#include "protocol.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::contribution {

PYOBF_NATIVE_CFF_SDK Result request(const BootstrapContextLease &expected,
    std::uint32_t routing_tag, const Site &point) noexcept {
    if (routing_tag == 0 || point.domain == 0 || point.function == 0 || point.site == 0 || point.source == 0)
        return {BootstrapContextStatus::invalid_request, 0};
    const auto generation = expected.generation();
    if (generation == 0) return {expected.availability(), 0};
    const Message message{context_protocol_version, sizeof(Message), routing_tag, 0, generation, point, 0};
    const auto result = call_bound_bootstrap(expected, {routing_tag, &message, sizeof(message)});
    if (result.status != BootstrapContextStatus::ok) return {result.status, 0};
    const auto word = static_cast<std::uint32_t>(result.value);
    if (static_cast<std::uint32_t>(result.value >> 32) != context_reply_tag || word == 0)
        return {BootstrapContextStatus::invalid_request, 0};
    return {BootstrapContextStatus::ok, word};
}

}  // namespace pyobfuscator::native::contribution
