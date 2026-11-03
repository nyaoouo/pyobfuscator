#include "runtime_fixture.hpp"

#include <cstring>

namespace decoy_fixture {
const std::uint8_t *hash_material = nullptr, *active_key = nullptr;
std::size_t hash_material_size = 0;
bool active_key_erased = false;
}

namespace pyobfuscator::native::platform {
bool hash_sha256_actual(const std::uint8_t *, std::size_t, std::uint8_t *) noexcept;
bool decrypt_payload_actual(const std::uint8_t *, std::size_t, const std::uint8_t *,
                           const std::uint8_t *, const std::uint8_t *, std::uint8_t *) noexcept;
bool decrypt_aead_actual(const std::uint8_t *, std::size_t, const std::uint8_t *, const std::uint8_t *,
                        const std::uint8_t *, const std::uint8_t *, std::size_t, std::uint8_t *) noexcept;

bool hash_sha256(const std::uint8_t *bytes, std::size_t size, std::uint8_t *digest) noexcept {
    using namespace decoy_fixture;
    require(hash_material == nullptr, "previous serialization erased");
    hash_material = bytes; hash_material_size = size;
    const bool decoy = counters.decoy_started;
    if (decoy) {
        ++counters.decoy_hashes;
        require(decoy_fold != nullptr && size >= sizeof(counters.decoy_fold), "independent decoy fold storage");
        const auto *words = decoy_fold->words;
        for (unsigned lane = 0; lane != 8; ++lane) {
            std::uint32_t observed = 0;
            for (unsigned byte = 0; byte != 4; ++byte)
                observed |= std::uint32_t(bytes[size - 32 + lane * 4 + byte]) << (byte * 8);
            require(observed == words[lane], "key serialization reads actual decoy fold");
            counters.decoy_fold[lane] = observed;
        }
    } else ++counters.real_hashes;
    if (!(decoy ? counters.decoy_hash_succeeds : counters.real_hash_succeeds)) {
        PYOBF_NATIVE_ERASE(digest, 32);
        return false;
    }
    return hash_sha256_actual(bytes, size, digest);
}
namespace {
void observe_key(const std::uint8_t *key) noexcept {
    using namespace decoy_fixture;
    require(active_key == nullptr && hash_material == nullptr, "separate retired key and serialization");
    active_key = key; active_key_erased = false; ++counters.keys;
}
}
bool decrypt_payload(const std::uint8_t *bytes, std::size_t size, const std::uint8_t *key,
                     const std::uint8_t *nonce, const std::uint8_t *tag, std::uint8_t *plaintext) noexcept {
    ++decoy_fixture::counters.real_decrypts;
    observe_key(key);
    return decrypt_payload_actual(bytes, size, key, nonce, tag, plaintext);
}
bool decrypt_aead(const std::uint8_t *bytes, std::size_t size, const std::uint8_t *key, const std::uint8_t *nonce,
                  const std::uint8_t *tag, const std::uint8_t *aad, std::size_t aad_size, std::uint8_t *plaintext) noexcept {
    using namespace decoy_fixture;
    require(counters.decoy_started && real_context != nullptr &&
            PYOBF_NATIVE_ATOMIC_LOAD32(&real_context->phase) == static_cast<std::uint32_t>(demo::LifecyclePhase::retired),
            "real admission retired before decoy CNG");
    ++counters.decoy_decrypts;
    observe_key(key);
    if (!counters.decoy_aead_succeeds) return false;
    return decrypt_aead_actual(bytes, size, key, nonce, tag, aad, aad_size, plaintext);
}
}  // namespace pyobfuscator::native::platform
