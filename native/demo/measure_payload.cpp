#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "bootstrap/handoff.hpp"
#include "contribution/protocol.hpp"
#include "pyobfuscator_native/contribution.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {
using namespace pyobfuscator::native;
using namespace pyobfuscator::native::demo;
using Clock = std::chrono::steady_clock;
constexpr unsigned startup_samples = 20, hot_samples = 5, hot_iterations = 128;
volatile std::uint64_t sink = 0;
struct Source { std::uint32_t routing, words[8]; std::uint64_t queries = 0; };

void require(bool condition) {
    if (!condition) { std::fputs("actual payload measurement failed\n", stderr); std::exit(1); }
}
void borrowed_destroy(void *) noexcept {}
void observe(std::uint32_t, void *) {}
BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *opaque) noexcept {
    auto &source = *static_cast<Source *>(opaque);
    if (request.operation_id != source.routing || request.input == nullptr)
        return {BootstrapContextStatus::invalid_request, 0};
    if (request.input_size == sizeof(LifecycleMessage)) return {BootstrapContextStatus::ok, 1};
    if (request.input_size != sizeof(contribution::Message)) return {BootstrapContextStatus::invalid_request, 0};
    const auto &message = *static_cast<const contribution::Message *>(request.input);
    if (message.version != contribution::context_protocol_version || message.size != sizeof(message) ||
            message.routing_tag != source.routing || message.reserved || message.tail_reserved)
        return {BootstrapContextStatus::invalid_request, 0};
    ++source.queries;
    const auto result = contribution::derive(source.words, message.routing_tag, message.point);
    return {result.status, result.status == BootstrapContextStatus::ok ?
        (std::uint64_t(contribution::context_reply_tag) << 32) | result.word : 0};
}
int reference(int value) { return value < 0 ? -value + 11 : value == 0 ? 17 : value * 3 + 1; }

struct Loaded {
    HMODULE image;
    InnerEntry entry;
    BootstrapContextCreation context;
    BootstrapContextLease expected;
    BootstrapContextBindingCreation publication{};
    PayloadHandoff handoff;

    Loaded(const char *path, Source &source) : image(LoadLibraryA(path)),
        entry(image ? reinterpret_cast<InnerEntry>(GetProcAddress(image, "pyobf_native_inner_entry")) : nullptr),
        context(create_bootstrap_context({bootstrap_context_abi_version, dispatch, &source, borrowed_destroy})),
        expected(context.owner.lease()),
        handoff{handoff_abi_version, source.routing, expected.generation(), &expected, &publication, observe, nullptr} {
        require(image && entry && context.status == BootstrapContextStatus::ok);
    }
    void call(int value) {
        require(entry(&handoff, value) == reference(value));
        publication.binding.reset();
    }
    ~Loaded() {
        context.owner.close();
        require(context.owner.quiescent());
        publication.binding.reset(); expected.reset(); context.owner = {};
        require(FreeLibrary(image) != 0);
    }
};
double startup(const char *path, Source &source) {
    const auto begin = Clock::now();
    { Loaded loaded(path, source); loaded.call(7); }
    return std::chrono::duration<double, std::micro>(Clock::now() - begin).count();
}
double hot(Loaded &loaded) {
    const auto begin = Clock::now();
    for (unsigned index = 0; index != hot_iterations; ++index) loaded.call(static_cast<int>(index % 17) - 8);
    sink = hot_iterations;
    return std::chrono::duration<double, std::nano>(Clock::now() - begin).count() / hot_iterations;
}
double median(std::vector<double> values) { std::sort(values.begin(), values.end()); return values[values.size() / 2]; }
}

int main(int argc, char **argv) {
    require(argc == 4);
    Source baseline{}, protected_source{};
    auto *input = std::fopen(argv[3], "rb");
    require(input != nullptr);
    // Measurement-only input: explicit little-endian routing and eight private words.
    std::uint32_t decoded[9]{};
    for (auto &word : decoded) for (unsigned byte = 0; byte != 4; ++byte) {
        const auto value = std::fgetc(input); require(value != EOF);
        word |= std::uint32_t(value) << (8 * byte);
    }
    require(std::fgetc(input) == EOF && std::fclose(input) == 0);
    baseline.routing = protected_source.routing = decoded[0];
    for (unsigned index = 0; index != 8; ++index) baseline.words[index] = protected_source.words[index] = decoded[index + 1];
    std::vector<double> first, second, first_hot, second_hot;
    for (unsigned sample = 0; sample != startup_samples; ++sample) {
        if (sample % 2) { second.push_back(startup(argv[2], protected_source)); first.push_back(startup(argv[1], baseline)); }
        else { first.push_back(startup(argv[1], baseline)); second.push_back(startup(argv[2], protected_source)); }
    }
    {
        Loaded plain(argv[1], baseline), protected_payload(argv[2], protected_source);
        for (unsigned sample = 0; sample != hot_samples; ++sample) {
            if (sample % 2) { second_hot.push_back(hot(protected_payload)); first_hot.push_back(hot(plain)); }
            else { first_hot.push_back(hot(plain)); second_hot.push_back(hot(protected_payload)); }
        }
    }
    require(baseline.queries == 0 && protected_source.queries > 0);
    std::printf("baseline_startup_us=%.6f\nprotected_startup_us=%.6f\nbaseline_hot_ns=%.6f\nprotected_hot_ns=%.6f\n",
        median(first), median(second), median(first_hot), median(second_hot));
    std::printf("startup_samples=%u\nhot_samples=%u\nhot_iterations=%u\nprotected_queries=%llu\n",
        startup_samples, hot_samples, hot_iterations, static_cast<unsigned long long>(protected_source.queries));
}
