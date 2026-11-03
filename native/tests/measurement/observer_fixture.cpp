#include "observer_fixture.hpp"

#include <cstring>

namespace observer_test {
native::measurement::reference::Identity identity{};
std::uint32_t words[8]{};
std::vector<std::uint8_t> package, plaintext;
unsigned pin_attempts = 0, pins = 0, unpins = 0, fail_pin = 0;
bool fail_release = false, fail_access = false, fail_body = false;
bool scope_material = false;
namespace {
std::uint8_t *key = nullptr;
unsigned key_erases = 0;
void hashed(std::uint8_t *value) { require(key == nullptr, "one factory key at a time"); key = value; }
void erased(void *value, std::size_t size) {
    if (value == key && key != nullptr && size == 32) {
        for (unsigned i = 0; i != 32; ++i) require(key[i] == 0, "observer factory key erased");
        key = nullptr; ++key_erases;
    }
}
}
void anchor() {}
void balanced() {
    require(capture_test::counters.views == 0 && capture_test::counters.allocations == capture_test::counters.releases &&
        pins == unpins, "observer allocations/views/provider code still owned");
}
void reset() {
    balanced(); capture_test::reset_fixture();
    pin_attempts = pins = unpins = fail_pin = 0; fail_release = fail_access = fail_body = false;
    scope_material = false;
    capture_test::faults.fixed_clock = true;
}
observer::Creation make(observer::Policy policy, const observer::ReaderBinding *reader) {
    key = nullptr; key_erases = 0;
    capture_test::on_hash = hashed; capture_test::on_erased = erased;
    auto result = observer::create(package.data(), package.size(), identity, words, {policy, anchor, 1, reader});
    capture_test::on_hash = nullptr; capture_test::on_erased = nullptr;
    require(key == nullptr && key_erases == 1, "factory key survived success/failure");
    return result;
}
internal::State &state(const native::BootstrapContextLease &lease) {
    return *static_cast<internal::State *>(native::detail::BootstrapContextAccess::state(lease)->spec.user_data);
}
}
namespace pyobfuscator::native::platform {
std::uint32_t native_byte_order() noexcept { return 1; }
bool decrypt_aead(const std::uint8_t *, std::size_t size, const std::uint8_t *key,
        const std::uint8_t *, const std::uint8_t *, const std::uint8_t *, std::size_t,
        std::uint8_t *output) noexcept {
    using namespace observer_test;
    for (unsigned i = 0; i != 32; ++i) require(key[i] == 0xdd, "mock derivation used");
    if (!size) return !fail_access;
    if (scope_material && size == 32) { std::memset(output, 0xcc, size); return !fail_body; }
    require(size == plaintext.size(), "typed reference fixture capacity");
    std::memcpy(output, plaintext.data(), size); return !fail_body;
}
CodeLease retain_code(CodeAddress) noexcept {
    ++observer_test::pin_attempts;
    if (observer_test::pin_attempts == observer_test::fail_pin) return {};
    ++observer_test::pins; return {reinterpret_cast<void *>(1)};
}
bool release_code(CodeLease lease) noexcept {
    if (lease.module != nullptr) ++observer_test::unpins;
    return !observer_test::fail_release;
}
}
