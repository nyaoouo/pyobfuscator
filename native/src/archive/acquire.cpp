#include "format.hpp"

#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

#include <cstring>
#include <limits>

namespace pyobfuscator::native::archive {
namespace {

PYOBF_NATIVE_CFF_SDK bool overlaps(const void *left, std::size_t left_size,
                                   const void *right, std::size_t right_size) noexcept {
    if (left_size == 0 || right_size == 0) return false;
    const auto first = reinterpret_cast<std::uintptr_t>(left);
    const auto second = reinterpret_cast<std::uintptr_t>(right);
    const auto maximum = std::numeric_limits<std::uintptr_t>::max();
    if (left_size > maximum - first || right_size > maximum - second) return true;
    return first < second + right_size && second < first + left_size;
}

PYOBF_NATIVE_CFF_SDK bool verify_access(const RecordView &record, const std::uint8_t *key) noexcept {
    constexpr std::uint8_t domain[] = "pyobf-native-archive-access-v1";
    std::uint8_t aad[sizeof(domain) - 1 + header_bytes + 68];
    std::memcpy(aad, domain, sizeof(domain) - 1);
    std::memcpy(aad + sizeof(domain) - 1, record.header, header_bytes);
    std::memcpy(aad + sizeof(domain) - 1 + header_bytes, record.descriptor, 68);
    return PYOBF_NATIVE_AEAD_DECRYPT(nullptr, 0, key, record.descriptor + 68,
                                    record.descriptor + 80, aad, sizeof(aad), nullptr);
}

PYOBF_NATIVE_CFF_SDK bool decode(const RecordView &record, const std::uint8_t *key,
                                std::uint8_t *destination) noexcept {
    constexpr std::uint8_t domain[] = "pyobf-native-archive-body-v1";
    std::uint8_t aad[sizeof(domain) - 1 + header_bytes + record_core_bytes];
    std::memcpy(aad, domain, sizeof(domain) - 1);
    std::memcpy(aad + sizeof(domain) - 1, record.header, header_bytes);
    std::memcpy(aad + sizeof(domain) - 1 + header_bytes, record.descriptor, record_core_bytes);
    return PYOBF_NATIVE_AEAD_DECRYPT(record.ciphertext, record.size, key, record.descriptor + 40,
                                    record.descriptor + 52, aad, sizeof(aad), destination) &&
           valid_plaintext(record, destination);
}

}  // namespace

PYOBF_NATIVE_CFF_SDK Status acquire_record(const std::uint8_t *package, std::size_t package_size,
                                           std::uint32_t record, std::uint8_t *destination,
                                           std::size_t capacity, Cache &cache, const std::uint8_t *key) noexcept {
    RecordView view{};
    const auto parsed = parse_record(package, package_size, record, view);
    if (parsed != Status::ready) return parsed;
    if (key == nullptr || capacity < view.size || (view.size != 0 && destination == nullptr) ||
        reinterpret_cast<std::uintptr_t>(destination) % view.alignment != 0 ||
        overlaps(destination, view.size, package, package_size) ||
        overlaps(destination, view.size, &cache, sizeof(cache))) return Status::invalid_storage;
    if (!verify_access(view, key)) return Status::verification_failed;
    for (;;) {
        const auto state = PYOBF_NATIVE_ATOMIC_LOAD32(&cache.state_);
        if (state == 0) {
            if (PYOBF_NATIVE_ATOMIC_CAS32(&cache.state_, 0, 1) != 0) continue;
            cache.package_ = package;
            cache.package_size_ = package_size;
            cache.record_ = record;
            cache.destination_ = destination;
            cache.capacity_ = capacity;
            const bool ready = decode(view, key, destination);
            if (!ready) PYOBF_NATIVE_ERASE(destination, view.size);
            PYOBF_NATIVE_ATOMIC_STORE32(&cache.state_, ready ? 2 : 3);
            return ready ? Status::ready : Status::decode_failed;
        }
        if (state == 1) {
            PYOBF_NATIVE_SPIN_PAUSE();
            continue;
        }
        if (state != 2 && state != 3) return Status::invalid_cache;
        if (cache.package_ != package || cache.package_size_ != package_size || cache.record_ != record ||
            cache.destination_ != destination || cache.capacity_ != capacity) return Status::binding_mismatch;
        return state == 2 ? Status::ready : Status::decode_failed;
    }
}

}  // namespace pyobfuscator::native::archive
