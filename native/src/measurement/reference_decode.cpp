#include "reference_internal.hpp"
#include "archive/format.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::reference {

PYOBF_NATIVE_CFF_SDK Reference open(const std::uint8_t *package, std::size_t size,
        const Identity &identity, const std::uint32_t (&words)[8]) noexcept {
    const Identity expected = identity;
    Reference result;
    if (!detail::valid_identity(expected)) { result.fail(Status::invalid_identity); return result; }
    archive::RecordView record{};
    if (size != expected.capacity || archive::parse_record(package, size, 0, record) != archive::Status::ready ||
            detail::read32(package + 12) != 1 || record.kind != archive::Kind::bytes || record.width != 8 ||
            record.alignment != 1 || record.size != size - detail::archive_overhead ||
            record.ciphertext != package + detail::archive_overhead) {
        result.fail(Status::invalid_record); return result;
    }
    std::uint8_t key[32]{};
    if (!detail::derive_key(expected, words, key)) { result.fail(Status::crypto_failed); return result; }
    auto *plaintext = static_cast<std::uint8_t *>(PYOBF_NATIVE_ALLOCATE(record.size));
    if (plaintext == nullptr) {
        PYOBF_NATIVE_ERASE(key, sizeof(key)); result.fail(Status::allocation_failed); return result;
    }
    archive::Cache cache;
    const auto acquired = archive::acquire_record(package, size, 0, plaintext, record.size, cache, key);
    PYOBF_NATIVE_ERASE(key, sizeof(key));
    auto status = acquired == archive::Status::ready ? detail::decode_payload(plaintext, record.size, expected, result) :
        Status::authentication_failed;
    PYOBF_NATIVE_ERASE(plaintext, record.size); PYOBF_NATIVE_RELEASE(plaintext);
    if (status != Status::ok) { result.fail(status); return result; }
    result.status_ = Status::ok;
    return result;
}

}  // namespace pyobfuscator::native::measurement::reference
