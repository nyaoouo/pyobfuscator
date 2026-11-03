#include "scope.hpp"
#include "archive/format.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::contribution::scoped::detail {
PYOBF_NATIVE_CFF_SDK Result authenticated_material(const path_fold::Storage &fold, const std::uint8_t *package,
        std::size_t size, const measurement::observer::Snapshot &snapshot, std::uint32_t routing, const Site &point) noexcept {
    static_assert(material_bytes == archive::header_bytes + archive::record_bytes + 32);
    Result result;
    archive::RecordView record{};
    if (size != material_bytes || archive::parse_record(package, size, 0, record) != archive::Status::ready ||
            package[12] != 1 || package[13] != 0 || package[14] != 0 || package[15] != 0 ||
            record.kind != archive::Kind::bytes || record.width != 8 || record.alignment != 1 || record.size != 32 ||
            record.ciphertext != package + archive::header_bytes + archive::record_bytes) {
        result.status = BootstrapContextStatus::invalid_request; return result;
    }
    constexpr release::Record expansion{"PYOBF-RELKEY-v2", 2, 64, {}, {}};
    constexpr char domain[] = "pyobf.native.contribution.scope.material.v1";
    std::uint8_t key[32]{}, material[32]{}, frame[sizeof(domain) + 32]{};
    std::uint32_t words[8]{};
    archive::Cache cache;
    result.material.material = release::measured::reconstruct(fold, expansion, snapshot, key);
    if (result.material.material.status == release::measured::Status::ok) {
        for (unsigned index = 0; index != sizeof(domain); ++index) frame[index] = domain[index];
        for (unsigned index = 0; index != 32; ++index) frame[sizeof(domain) + index] = key[index];
        if (!PYOBF_NATIVE_SHA256(frame, sizeof(frame), key))
            result.material.material.status = release::measured::Status::crypto_failed;
        else {
            result.authentication = archive::acquire_record(package, size, 0, material, sizeof(material), cache, key);
            if (result.authentication == archive::Status::ready) {
                for (unsigned index = 0; index != 8; ++index)
                    for (unsigned byte = 0; byte != 4; ++byte)
                        words[index] |= std::uint32_t(material[index * 4 + byte]) << (byte * 8);
                result.material.value = contribution::derive(words, routing, point);
                result.material.status = result.material.value.status == BootstrapContextStatus::ok ?
                    measured::Status::ok : measured::Status::derivation_failed;
                result.status = result.material.value.status;
            }
        }
    }
    PYOBF_NATIVE_ERASE(words, sizeof(words));
    PYOBF_NATIVE_ERASE(material, sizeof(material));
    PYOBF_NATIVE_ERASE(key, sizeof(key));
    PYOBF_NATIVE_ERASE(frame, sizeof(frame));
    PYOBF_NATIVE_ERASE(&cache, sizeof(cache));
    return result;
}
}
