#pragma once

#include <cstddef>
#include <cstdint>
#include <atomic>

namespace pyobfuscator::native::platform {

using AtomicWord32 = std::atomic<std::uint32_t>;
using CodeAddress = void (*)();
struct CodeLease { void *module = nullptr; };

void *allocate(std::size_t size) noexcept;
void release(void *memory) noexcept;
void erase(void *memory, std::size_t size) noexcept;
// Caller supplies 32 writable bytes; false erases that output. Empty input may be null.
bool hash_sha256(const std::uint8_t *bytes, std::size_t length, std::uint8_t *digest) noexcept;
bool decrypt_payload(const std::uint8_t *ciphertext, std::size_t length,
                     const std::uint8_t *key, const std::uint8_t *nonce,
                     const std::uint8_t *tag, std::uint8_t *plaintext) noexcept;
bool decrypt_aead(const std::uint8_t *ciphertext, std::size_t length,
                  const std::uint8_t *key, const std::uint8_t *nonce,
                  const std::uint8_t *tag, const std::uint8_t *aad,
                  std::size_t aad_length, std::uint8_t *plaintext) noexcept;
std::uint32_t atomic_load32(const AtomicWord32 *value) noexcept;
std::uint32_t atomic_compare_exchange32(AtomicWord32 *value, std::uint32_t expected,
                                       std::uint32_t desired) noexcept;
void atomic_store32(AtomicWord32 *value, std::uint32_t desired) noexcept;
void spin_pause() noexcept;
CodeLease retain_code(CodeAddress address) noexcept;
bool release_code(CodeLease lease) noexcept;
std::uint32_t native_byte_order() noexcept;
[[noreturn]] void protection_failure(std::uint32_t reason) noexcept;
void *load_payload(const std::uint8_t *bytes, std::size_t length) noexcept;
void *resolve_payload_entry(void *image) noexcept;
void unload_payload(void *image) noexcept;

}  // namespace pyobfuscator::native::platform

// Call sites use semantic operations; only the selected backend contains OS API calls.
#define PYOBF_NATIVE_ALLOCATE(size) ::pyobfuscator::native::platform::allocate(size)
#define PYOBF_NATIVE_RELEASE(memory) ::pyobfuscator::native::platform::release(memory)
#define PYOBF_NATIVE_ERASE(memory, size) ::pyobfuscator::native::platform::erase(memory, size)
#define PYOBF_NATIVE_SHA256(...) ::pyobfuscator::native::platform::hash_sha256(__VA_ARGS__)
#define PYOBF_NATIVE_DECRYPT(...) ::pyobfuscator::native::platform::decrypt_payload(__VA_ARGS__)
#define PYOBF_NATIVE_AEAD_DECRYPT(...) ::pyobfuscator::native::platform::decrypt_aead(__VA_ARGS__)
#define PYOBF_NATIVE_ATOMIC_LOAD32(value) ::pyobfuscator::native::platform::atomic_load32(value)
#define PYOBF_NATIVE_ATOMIC_CAS32(...) ::pyobfuscator::native::platform::atomic_compare_exchange32(__VA_ARGS__)
#define PYOBF_NATIVE_ATOMIC_STORE32(...) ::pyobfuscator::native::platform::atomic_store32(__VA_ARGS__)
#define PYOBF_NATIVE_SPIN_PAUSE() ::pyobfuscator::native::platform::spin_pause()
#define PYOBF_NATIVE_RETAIN_CODE(address) ::pyobfuscator::native::platform::retain_code(address)
#define PYOBF_NATIVE_RELEASE_CODE(lease) ::pyobfuscator::native::platform::release_code(lease)
#define PYOBF_NATIVE_BYTE_ORDER() ::pyobfuscator::native::platform::native_byte_order()
#define PYOBF_NATIVE_PROTECTION_FAILURE(reason) ::pyobfuscator::native::platform::protection_failure(reason)
#define PYOBF_NATIVE_LOAD(bytes, length) ::pyobfuscator::native::platform::load_payload(bytes, length)
#define PYOBF_NATIVE_RESOLVE(image) ::pyobfuscator::native::platform::resolve_payload_entry(image)
#define PYOBF_NATIVE_UNLOAD(image) ::pyobfuscator::native::platform::unload_payload(image)
