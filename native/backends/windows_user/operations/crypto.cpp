#include "pyobfuscator_native/system_ops.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstring>
#include <limits>

namespace pyobfuscator::native::platform {

namespace {
constexpr std::uint8_t aad[] = "pyobf-native-demo-v1";
}

bool decrypt_payload(const std::uint8_t *ciphertext, std::size_t length,
                     const std::uint8_t *key, const std::uint8_t *nonce,
                     const std::uint8_t *tag, std::uint8_t *plaintext) noexcept {
    return decrypt_aead(ciphertext, length, key, nonce, tag, aad, sizeof(aad) - 1, plaintext);
}

bool decrypt_aead(const std::uint8_t *ciphertext, std::size_t length,
                  const std::uint8_t *key, const std::uint8_t *nonce,
                  const std::uint8_t *tag, const std::uint8_t *authenticated_data,
                  std::size_t aad_length, std::uint8_t *plaintext) noexcept {
    if (length > (std::numeric_limits<ULONG>::max)() || aad_length > (std::numeric_limits<ULONG>::max)() ||
        key == nullptr || nonce == nullptr || tag == nullptr ||
        (length != 0 && (ciphertext == nullptr || plaintext == nullptr)) ||
        (aad_length != 0 && authenticated_data == nullptr)) {
        return false;
    }
    std::uint8_t empty_input = 0, empty_output = 0;
    // A null output pointer asks CNG for a size; it must never bypass empty-message auth.
    auto *input = length == 0 ? &empty_input : const_cast<PUCHAR>(ciphertext);
    auto *output = length == 0 ? &empty_output : plaintext;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE cipher_key = nullptr;
    PUCHAR key_object = nullptr;
    ULONG key_object_size = 0;
    ULONG returned = 0;
    bool success = false;

    do {
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) {
            break;
        }
        if (BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                             reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                             sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) {
            break;
        }
        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                             reinterpret_cast<PUCHAR>(&key_object_size),
                             sizeof(key_object_size), &returned, 0) < 0) {
            break;
        }
        key_object = static_cast<PUCHAR>(PYOBF_NATIVE_ALLOCATE(key_object_size));
        if (key_object == nullptr ||
            BCryptGenerateSymmetricKey(algorithm, &cipher_key, key_object, key_object_size,
                                       const_cast<PUCHAR>(key), 32, 0) < 0) {
            break;
        }
        std::uint8_t tag_copy[16];
        std::memcpy(tag_copy, tag, sizeof(tag_copy));
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication;
        BCRYPT_INIT_AUTH_MODE_INFO(authentication);
        authentication.pbNonce = const_cast<PUCHAR>(nonce);
        authentication.cbNonce = 12;
        authentication.pbAuthData = const_cast<PUCHAR>(authenticated_data);
        authentication.cbAuthData = static_cast<ULONG>(aad_length);
        authentication.pbTag = tag_copy;
        authentication.cbTag = sizeof(tag_copy);
        ULONG plaintext_size = 0;
        success = BCryptDecrypt(cipher_key, input,
                                static_cast<ULONG>(length), &authentication, nullptr, 0,
                                output, static_cast<ULONG>(length), &plaintext_size, 0) >= 0 &&
                  plaintext_size == length;
    } while (false);

    if (cipher_key != nullptr) {
        BCryptDestroyKey(cipher_key);
    }
    PYOBF_NATIVE_ERASE(key_object, key_object_size);
    PYOBF_NATIVE_RELEASE(key_object);
    if (algorithm != nullptr) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (!success) PYOBF_NATIVE_ERASE(plaintext, length);
    return success;
}

}  // namespace pyobfuscator::native::platform
