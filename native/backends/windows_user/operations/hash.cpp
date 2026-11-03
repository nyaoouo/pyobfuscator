#include "pyobfuscator_native/system_ops.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <limits>

namespace pyobfuscator::native::platform {

bool hash_sha256(const std::uint8_t *bytes, std::size_t length, std::uint8_t *digest) noexcept {
    if (digest == nullptr) return false;
    if ((length != 0 && bytes == nullptr) || length > (std::numeric_limits<ULONG>::max)()) {
        PYOBF_NATIVE_ERASE(digest, 32);
        return false;
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    PUCHAR object = nullptr;
    ULONG object_size = 0, digest_size = 0, returned = 0;
    bool success = false;
    do {
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) break;
        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
                sizeof(object_size), &returned, 0) < 0 || returned != sizeof(object_size) || object_size == 0) break;
        if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&digest_size),
                sizeof(digest_size), &returned, 0) < 0 || returned != sizeof(digest_size) || digest_size != 32) break;
        object = static_cast<PUCHAR>(PYOBF_NATIVE_ALLOCATE(object_size));
        if (object == nullptr || BCryptCreateHash(algorithm, &hash, object, object_size, nullptr, 0, 0) < 0) break;
        if (length != 0 && BCryptHashData(hash, const_cast<PUCHAR>(bytes), static_cast<ULONG>(length), 0) < 0) break;
        success = BCryptFinishHash(hash, digest, 32, 0) >= 0;
    } while (false);
    // CNG retains the object storage through hash destruction.
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (object != nullptr) {
        PYOBF_NATIVE_ERASE(object, object_size);
        PYOBF_NATIVE_RELEASE(object);
    }
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!success) PYOBF_NATIVE_ERASE(digest, 32);
    return success;
}

}  // namespace pyobfuscator::native::platform
