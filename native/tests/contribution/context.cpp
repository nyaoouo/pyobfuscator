#include "pyobfuscator_native/contribution.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "pyobfuscator_native/system_ops.hpp"
#include "contribution/protocol.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace {
using namespace pyobfuscator::native;
constexpr std::uint32_t route = 0x11883377;
constexpr contribution::Site point{1, 2, 3, 4, 0x12345678};
enum class Mode { normal, zero, wrong_tag, error, reenter, reset_inside, blocked };
std::atomic<unsigned> destroyed{0};
void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "contribution context failed: %s\n", message); std::abort(); }
}
struct Provider {
    std::uint32_t words[8]{1, 2, 3, 4, 5, 6, 7, 8};
    std::uint64_t generation = 0;
    std::atomic<unsigned> calls{0};
    std::atomic<bool> entered{false}, finish{false};
    Mode mode = Mode::normal;
    BootstrapContextOwner *owner = nullptr;
    BootstrapContextLease *expected = nullptr;
    BootstrapContextBinding *binding = nullptr;
    bool nested = false;
};
void destroy(void *opaque) noexcept {
    auto *provider = static_cast<Provider *>(opaque);
    PYOBF_NATIVE_ERASE(provider->words, sizeof(provider->words));
    ++destroyed; delete provider;
}
void borrowed_destroy(void *) noexcept {}
BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *opaque) noexcept {
    auto &provider = *static_cast<Provider *>(opaque);
    require(request.operation_id == route && request.input != nullptr && request.input_size == sizeof(contribution::Message), "bounded message framing");
    contribution::Message message;
    std::memcpy(&message, request.input, sizeof(message));
    require(message.version == 1 && message.size == sizeof(message) && message.routing_tag == route &&
            message.reserved == 0 && message.tail_reserved == 0 && message.generation == provider.generation, "complete client snapshot");
    ++provider.calls;
    if (provider.mode == Mode::zero) return {BootstrapContextStatus::ok, std::uint64_t(contribution::context_reply_tag) << 32};
    if (provider.mode == Mode::wrong_tag) return {BootstrapContextStatus::ok, 7};
    if (provider.mode == Mode::error) return {BootstrapContextStatus::unavailable, 0xffffffffffffffffull};
    if (provider.mode == Mode::reenter && !provider.nested) {
        provider.nested = true;
        auto nested = message.point; nested.current ^= 1;
        require(contribution::request(*provider.expected, route, nested).status == BootstrapContextStatus::ok, "reentrant owned acquisition");
    }
    if (provider.mode == Mode::reset_inside) {
        provider.owner->close(); provider.binding->reset(); provider.expected->reset(); *provider.owner = {};
        require(destroyed == 0, "captured call keeps provider through reentrant withdrawal");
    }
    if (provider.mode == Mode::blocked) {
        provider.entered.store(true);
        while (!provider.finish.load()) std::this_thread::yield();
    }
    const auto result = contribution::derive(provider.words, route, message.point);
    return {result.status, result.status == BootstrapContextStatus::ok ?
        (std::uint64_t(contribution::context_reply_tag) << 32) | result.word : 0};
}
void refused(const contribution::Result &result, BootstrapContextStatus status) {
    if (result.status != status || result.word != 0)
        std::fprintf(stderr, "contribution refusal status%u expected%u word-present%u\n",
            static_cast<unsigned>(result.status), static_cast<unsigned>(status), result.word != 0);
    require(result.status == status && result.word == 0, "failed acquisition exposes no usable word");
}
}

int main() {
    BootstrapContextLease empty;
    refused(contribution::request(empty, route, point), BootstrapContextStatus::unavailable);
    for (Mode mode : {Mode::normal, Mode::zero, Mode::wrong_tag, Mode::error, Mode::reenter, Mode::reset_inside, Mode::blocked}) {
        destroyed = 0;
        auto *provider = new Provider; provider->mode = mode;
        auto creation = create_bootstrap_context({bootstrap_context_abi_version, dispatch, provider, destroy});
        require(creation.status == BootstrapContextStatus::ok, "provider context created");
        auto expected = creation.owner.lease(); provider->generation = creation.owner.generation();
        provider->owner = &creation.owner; provider->expected = &expected;
        refused(contribution::request(expected, route, point), BootstrapContextStatus::unavailable);
        auto publication = bind_bootstrap_context(expected);
        require(publication.status == BootstrapContextStatus::ok, "strict context published"); provider->binding = &publication.binding;
        if (mode == Mode::blocked) {
            auto worker_lease = expected;
            contribution::Result result;
            std::thread worker([&] { result = contribution::request(worker_lease, route, point); });
            while (!provider->entered.load()) std::this_thread::yield();
            creation.owner.close();
            require(!creation.owner.quiescent(), "in-flight source prevents quiescence");
            publication.binding.reset(); expected.reset(); creation.owner = {};
            require(destroyed == 0, "blocked source keeps userdata and code");
            provider->finish = true; worker.join();
            require(result.status == BootstrapContextStatus::ok && result.word != 0, "admitted source may finish after close");
            refused(contribution::request(worker_lease, route, point), BootstrapContextStatus::unavailable);
            worker_lease.reset();
        } else {
            const auto result = contribution::request(expected, route, point);
            if (mode == Mode::zero || mode == Mode::wrong_tag) refused(result, BootstrapContextStatus::invalid_request);
            else if (mode == Mode::error) refused(result, BootstrapContextStatus::unavailable);
            else require(result.status == BootstrapContextStatus::ok && result.word != 0, "derived nonzero contribution");
            if (mode == Mode::normal) {
                std::printf("contribution-word %u\n", result.word);
                for (unsigned field = 0; field != 5; ++field) {
                    auto changed = point;
                    if (field == 0) ++changed.domain;
                    if (field == 1) ++changed.function;
                    if (field == 2) ++changed.site;
                    if (field == 3) ++changed.source;
                    if (field == 4) ++changed.current;
                    const auto altered = contribution::request(expected, route, changed);
                    require(altered.status == BootstrapContextStatus::ok && altered.word != result.word, "each public binding field influences fixture word");
                    std::printf("contribution-word %u\n", altered.word);
                }
                auto other = create_bootstrap_context({bootstrap_context_abi_version, dispatch, provider, borrowed_destroy});
                require(other.status == BootstrapContextStatus::ok, "foreign context is genuinely valid");
                auto foreign = other.owner.lease();
                refused(contribution::request(foreign, route, point), BootstrapContextStatus::context_mismatch);
                for (unsigned field = 0; field != 4; ++field) {
                    auto bad = point;
                    if (field == 0) bad.domain = 0; if (field == 1) bad.function = 0;
                    if (field == 2) bad.site = 0; if (field == 3) bad.source = 0;
                    refused(contribution::request(expected, route, bad), BootstrapContextStatus::invalid_request);
                }
                refused(contribution::request(expected, 0, point), BootstrapContextStatus::invalid_request);
                std::vector<std::thread> workers;
                for (unsigned index = 0; index != 4; ++index) workers.emplace_back([&] {
                    for (unsigned call = 0; call != 16; ++call) {
                        const auto sample = contribution::request(expected, route, point);
                        require(sample.status == BootstrapContextStatus::ok && sample.word == result.word, "concurrent immutable provider and separate request storage");
                    }
                });
                for (auto &worker : workers) worker.join();
                creation.owner.close();
                refused(contribution::request(expected, route, point), BootstrapContextStatus::closed);
            }
            publication.binding.reset(); expected.reset(); creation.owner = {};
        }
        require(destroyed == 1, "provider destroyed exactly once after all captured uses");
    }
    std::puts("contribution context: actual CNG, strict identity, response framing, reentry, close/drain and four-thread acquisition verified");
}
