#include "measurement/reference.hpp"
#include "failure_fixture.hpp"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <vector>

namespace {
namespace reference = pyobfuscator::native::measurement::reference;
using namespace capture_test;
std::vector<std::uint8_t> plaintext;
bool fail_access = false, fail_body = false, reenter = false, nested = false;
unsigned decrypts = 0, key_erases = 0;
std::vector<std::uint8_t *> active_keys;
const std::vector<std::uint8_t> *active_package = nullptr;
reference::Identity active_identity{};
std::uint32_t active_words[8]{};

std::vector<std::uint8_t> read(const char *path) {
    auto *input = std::fopen(path, "rb"); require(input != nullptr, "reference fault input");
    std::vector<std::uint8_t> data;
    for (int value; (value = std::fgetc(input)) != EOF;) {
        require(data.size() < 512 * 1024, "reference fault file budget"); data.push_back(static_cast<std::uint8_t>(value));
    }
    require(!std::ferror(input) && std::fclose(input) == 0, "reference fault input read");
    return data;
}
bool blank(const reference::Reference &value) {
    const auto &descriptor = value.descriptor();
    if (descriptor.kind || descriptor.owner || descriptor.subject || descriptor.image_size || descriptor.preferred_base ||
            descriptor.range_count || descriptor.fixup_count || descriptor.ranges || descriptor.fixups) return false;
    for (unsigned index = 0; index != 32; ++index) if (value.expected_digest()[index]) return false;
    return true;
}
void hashed(std::uint8_t *key) {
    require(std::find(active_keys.begin(), active_keys.end(), key) == active_keys.end(), "reentrant key storage alias");
    active_keys.push_back(key);
}
void erased(void *memory, std::size_t size) {
    const auto found = std::find(active_keys.begin(), active_keys.end(), memory);
    if (found == active_keys.end() || size != 32) return;
    for (unsigned index = 0; index != 32; ++index) require((*found)[index] == 0, "derived key not erased");
    active_keys.erase(found); ++key_erases;
}
}

namespace pyobfuscator::native::platform {
std::uint32_t native_byte_order() noexcept { return 1; }
bool decrypt_aead(const std::uint8_t *, std::size_t length, const std::uint8_t *key,
        const std::uint8_t *, const std::uint8_t *, const std::uint8_t *, std::size_t,
        std::uint8_t *output) noexcept {
    ++decrypts;
    for (unsigned index = 0; index != 32; ++index) require(key[index] == 0xdd, "key derivation output not supplied");
    if (length == 0) return !fail_access;
    require(length == plaintext.size(), "plaintext fault fixture size");
    if (reenter && !nested) {
        nested = true;
        auto other = reference::open(active_package->data(), active_package->size(), active_identity, active_words);
        require(other.status() == reference::Status::ok, "reentrant decode blocked or mixed outer state");
        nested = false;
    }
    if (fail_body) { std::memset(output, 0xdd, length); return false; }
    std::memcpy(output, plaintext.data(), length); return true;
}
}

int main(int argc, char **argv) {
    require(argc == 4, "metadata/package/plaintext fault fixtures");
    const auto metadata = read(argv[1]), package = read(argv[2]); plaintext = read(argv[3]);
    require(metadata.size() == 84, "fault fixture independent inputs");
    reference::Identity identity{}; std::uint32_t words[8]{};
    std::memcpy(&identity, metadata.data(), 52); std::memcpy(words, metadata.data() + 52, 32);
    active_package = &package; active_identity = identity; std::memcpy(active_words, words, 32);
    for (unsigned scenario = 0; scenario != 7; ++scenario) {
        reset_fixture(); decrypts = 0; key_erases = 0; active_keys.clear(); reenter = scenario == 6;
        on_hash = hashed; on_erased = erased;
        fail_access = scenario == 2; fail_body = scenario == 3;
        faults.hash = scenario == 0; faults.allocation = scenario == 1;
        faults.allocation_failure_at = scenario == 4 ? 2 : 0;
        auto result = reference::open(package.data(), package.size(), identity, words);
        const auto wanted = scenario == 0 ? reference::Status::crypto_failed :
            scenario == 1 || scenario == 4 ? reference::Status::allocation_failed :
            scenario < 4 ? reference::Status::authentication_failed : reference::Status::ok;
        require(result.status() == wanted, "reference fault source differs");
        if (wanted != reference::Status::ok) require(blank(result), "failed reference left usable metadata");
        else {
            require(decrypts == (reenter ? 4u : 2u) && counters.allocations == (reenter ? 4u : 2u),
                "successful/reentrant reference did not own independent storage"); result.reset();
        }
        require(key_erases == (reenter ? 2u : 1u) && active_keys.empty(), "key survived reference success/failure");
        require(counters.allocations == counters.releases, "reference fault retained allocation");
    }
    reset_fixture();
    std::puts("reference crypto/alloc/access/body faults, reentry, dirty plaintext/key erasure and owned cleanup pass");
}
