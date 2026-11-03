#include "session_fixture.hpp"

#include <cstring>

namespace session_fixture {
const std::uint8_t *hash_material = nullptr;
std::size_t hash_material_size = 0;
const std::uint8_t *active_key = nullptr;
bool active_key_erased = false;
}

namespace pyobfuscator::native::platform {
// These are separately compiled production implementations with test-only symbol
// names. Only allocation, loader and operation observations are supplied here.
bool hash_sha256_actual(const std::uint8_t *, std::size_t, std::uint8_t *) noexcept;
bool decrypt_payload_actual(const std::uint8_t *, std::size_t, const std::uint8_t *,
                            const std::uint8_t *, const std::uint8_t *, std::uint8_t *) noexcept;

bool hash_sha256(const std::uint8_t *bytes, std::size_t size, std::uint8_t *digest) noexcept {
    using namespace session_fixture;
    require(hash_material == nullptr, "previous serialization material was erased");
    hash_material = bytes;
    hash_material_size = size;
    ++counters.hashes;
    if (!counters.hash_succeeds) {
        PYOBF_NATIVE_ERASE(digest, 32);
        return false;
    }
    return hash_sha256_actual(bytes, size, digest);
}

bool decrypt_payload(const std::uint8_t *ciphertext, std::size_t size, const std::uint8_t *key,
                     const std::uint8_t *nonce, const std::uint8_t *tag, std::uint8_t *plaintext) noexcept {
    using namespace session_fixture;
    require(active_key == nullptr, "previous reconstructed key was retired");
    active_key = key;
    active_key_erased = false;
    ++counters.keys;
    ++counters.decrypts;
    if (fold_context != nullptr)
        std::memcpy(counters.decrypt_fold, fold_context->fold.words, sizeof(counters.decrypt_fold));
    if (!counters.authenticated) return false;
    return decrypt_payload_actual(ciphertext, size, key, nonce, tag, plaintext);
}
}
