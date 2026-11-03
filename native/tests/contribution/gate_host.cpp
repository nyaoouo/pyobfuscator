#include "pyobfuscator_native/contribution.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "contribution/protocol.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
#include "archive_host_support.hpp"
#endif
#ifdef PYOBF_CONTRIBUTION_HYBRID_TEST
#include "hybrid_host_support.hpp"
#endif
#ifdef PYOBF_CONTRIBUTION_REGION_TEST
#include "region_host_support.hpp"
#endif

using namespace pyobfuscator::native;
#ifdef PYOBF_CONTRIBUTION_PREPARATION_TEST
extern "C" int contribution_preparation_imported(int value) noexcept {
    volatile int retained = value;
    return retained;
}
#endif
extern "C" int contribution_compute(const BootstrapContextLease &, int) noexcept;
extern "C" int contribution_compute_global(int) noexcept;
#ifdef PYOBF_CONTRIBUTION_AUTO_TEST
extern "C" int contribution_switch(const BootstrapContextLease &, int) noexcept;
#endif
BootstrapContextLease contribution_fixture_expected;
#ifdef PYOBF_CONTRIBUTION_NORMALIZER_TEST
static unsigned normalizer_effects = 0;
extern "C" int contribution_normalizer_identity(int value) noexcept {
    ++normalizer_effects;
    return value;
}
#endif
namespace {
std::uint32_t words[8]{1, 2, 3, 4, 5, 6, 7, 8};
bool unavailable = false;
std::uint32_t failed_source = 0;
std::uint64_t generation = 0;
BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *) noexcept {
    if (request.operation_id != 7 || request.input == nullptr || request.input_size != sizeof(contribution::Message))
        return {BootstrapContextStatus::invalid_request, 0};
    contribution::Message message;
    std::memcpy(&message, request.input, sizeof(message));
    if (message.version != 1 || message.size != sizeof(message) || message.routing_tag != 7 || message.generation != generation ||
            message.reserved != 0 || message.tail_reserved != 0 || message.point.domain != 11 ||
            (message.point.function != 13 && message.point.function != 19
#ifdef PYOBF_CONTRIBUTION_AUTO_TEST
                && message.point.function != 23
#endif
#ifdef PYOBF_CONTRIBUTION_HYBRID_TEST
                && message.point.function != 29
#endif
#ifdef PYOBF_CONTRIBUTION_REGION_TEST
                && message.point.function != 31
#endif
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
                && message.point.function != 35
#endif
#ifdef PYOBF_CONTRIBUTION_HYBRID_SCALAR_TEST
                && message.point.function != 37
#endif
            ) || (message.point.source != 17
#ifdef PYOBF_CONTRIBUTION_GROUPED_TEST
                && message.point.source != 29 && message.point.source != 41
#endif
            ))
        return {BootstrapContextStatus::unavailable, 0};
    if (unavailable || message.point.source == failed_source) return {BootstrapContextStatus::unavailable, 0xffffffffffffffffull};
    const auto result = contribution::derive(words, 7, message.point);
    return {result.status, result.status == BootstrapContextStatus::ok ?
        (std::uint64_t(contribution::context_reply_tag) << 32) | result.word : 0};
}
int reference(int value) {
#ifdef PYOBF_CONTRIBUTION_NORMALIZER_TEST
    return value == 2 ? 41 : (((((value + 7) ^ 123) + 9) * 3) ^ 17) + 11;
#else
#ifdef PYOBF_CONTRIBUTION_SCALAR_DONOR_TEST
    value += value & 1;
#endif
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
    value = archive_reference(value);
#endif
    int result = 11;
    for (int index = 0; index != (value & 3) + 1; ++index)
        result += (value + index) & 1 ? value + 5 : value - 3;
    return result;
#endif
}
}
extern "C" std::uint32_t pyobf_native_contribution_word_v1(const BootstrapContextLease &,
    std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t) noexcept;
extern "C" std::uint32_t contribution_forwarded_word(const BootstrapContextLease &expected,
    std::uint32_t route, std::uint32_t domain, std::uint32_t function, std::uint32_t site,
    std::uint32_t source, std::uint32_t current) noexcept {
    return pyobf_native_contribution_word_v1(expected, route, domain, function, site, source, current);
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "normal";
    unsigned iterations = 1, warmups = 0;
#if defined(PYOBF_CONTRIBUTION_NORMALIZER_TEST) || defined(PYOBF_CONTRIBUTION_COST_TEST)
    const bool benchmark = argc > 2;
    if (benchmark) {
        char *end = nullptr;
        const auto count = std::strtoul(argv[2], &end, 10);
        if (argc != 3 || std::strcmp(mode, "normal") || *end != '\0' || count == 0 || count > 4096) return 64;
        iterations = static_cast<unsigned>(count); warmups = 1;
    }
    std::chrono::steady_clock::time_point measured_start;
#endif
    auto creation = create_bootstrap_context({bootstrap_context_abi_version, dispatch});
    if (creation.status != BootstrapContextStatus::ok) return 70;
    auto expected = creation.owner.lease();
    generation = expected.generation();
    auto binding = bind_bootstrap_context(expected);
    if (binding.status != BootstrapContextStatus::ok) return 71;
    BootstrapContextLease empty;
    auto other = create_bootstrap_context({bootstrap_context_abi_version, dispatch});
    auto foreign = other.owner.lease();
    if (!std::strcmp(mode, "wrong")) words[0] ^= 1;
    if (!std::strcmp(mode, "provider")) unavailable = true;
#ifdef PYOBF_CONTRIBUTION_GROUPED_TEST
    if (!std::strncmp(mode, "source-", 7)) failed_source = std::strtoul(mode + 7, nullptr, 10);
#endif
    if (!std::strcmp(mode, "closed")) creation.owner.close();
    if (!std::strcmp(mode, "unbound")) binding.binding.reset();
    const auto &lease = !std::strcmp(mode, "empty") ? empty : !std::strcmp(mode, "foreign") ? foreign : expected;
    contribution_fixture_expected = lease;
    if (!std::strcmp(mode, "fail-scalar")) {
        (void)pyobf_native_contribution_word_v1(empty, 7, 11, 13, 101, 17, 0x12345678);
        return 73;
    }
    const bool available = !std::strcmp(mode, "normal") || !std::strcmp(mode, "wrong") || (failed_source != 0 && failed_source != 17)
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
        || !std::strncmp(mode, "warm-", 5)
#endif
        ;
    std::uint32_t scalar = 0;
    if (available) scalar = pyobf_native_contribution_word_v1(lease, 7, 11, 13, 101, 17, 0x12345678);
    else {
        const auto refused = contribution::request(lease, 7, {11, 13, 101, 17, 0x12345678});
        if (refused.status == BootstrapContextStatus::ok || refused.word != 0) return 72;
    }
    if ((scalar != 0) != available) return 72;
    std::puts("gate-enter"); std::fflush(stdout);
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
    if (!std::strncmp(mode, "warm-", 5)) {
#ifdef PYOBF_CONTRIBUTION_HYBRID_TEST
        if (!hybrid_run(lease)) return 5;
#endif
        for (int value = -13; value <= 13; ++value)
            if (contribution_compute(lease, value) != reference(value)) return 8;
        std::puts("archive-warm"); std::fflush(stdout);
        if (!std::strcmp(mode, "warm-wrong")) words[0] ^= 1;
        if (!std::strcmp(mode, "warm-provider")) unavailable = true;
        if (!std::strcmp(mode, "warm-closed")) creation.owner.close();
        if (!std::strcmp(mode, "warm-unbound")) binding.binding.reset();
    }
#endif
#ifdef PYOBF_CONTRIBUTION_REGION_TEST
    if (!region_run(lease)) return 6;
#endif
#ifdef PYOBF_CONTRIBUTION_HYBRID_TEST
    if (!hybrid_run(lease)) return 5;
#endif
    for (unsigned repeat = 0; repeat != iterations + warmups; ++repeat) {
#if defined(PYOBF_CONTRIBUTION_NORMALIZER_TEST) || defined(PYOBF_CONTRIBUTION_COST_TEST)
        if (benchmark && repeat == warmups) measured_start = std::chrono::steady_clock::now();
#endif
        for (int value = -13; value <= 13; ++value) {
            if (contribution_compute(lease, value) != reference(value)) return 2;
            if (contribution_compute_global(value) != reference(value)) return 3;
#ifdef PYOBF_CONTRIBUTION_AUTO_TEST
            const auto switched = value == -9 || value == 3 ? value + 7 : value == -1 ? value * 2 : value == 2 ? 17 : value - 5;
            if (contribution_switch(lease, value) != switched + ((value & 1) ? 3 : 0)) return 4;
#endif
        }
    }
#ifdef PYOBF_CONTRIBUTION_NORMALIZER_TEST
    if (normalizer_effects != 52 * (iterations + warmups)) return 7;
#endif
#if defined(PYOBF_CONTRIBUTION_NORMALIZER_TEST) || defined(PYOBF_CONTRIBUTION_COST_TEST)
    if (benchmark) {
        const auto elapsed = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - measured_start).count();
        unsigned calls = 54 * iterations;
#ifdef PYOBF_CONTRIBUTION_AUTO_TEST
        calls += 27 * iterations;
#endif
        std::printf("gate-benchmark iterations=%u warmups=%u top_calls=%u elapsed_ns=%.0f\n", iterations, warmups, calls, elapsed);
    }
#endif
    std::puts("gate-normal-completed");
}
