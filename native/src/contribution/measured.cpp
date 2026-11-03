#include "measured.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::contribution::measured {
PYOBF_NATIVE_CFF_SDK Result derive(const path_fold::Storage &fold, const release::Record &record,
        const measurement::observer::Snapshot &snapshot, std::uint32_t routing_tag, const Site &point) noexcept {
    Result result;
    std::uint8_t material[32]{};
    std::uint32_t words[8]{};
    result.material = release::measured::reconstruct(fold, record, snapshot, material);
    if (result.material.status == release::measured::Status::ok) {
        if (snapshot.data().identity.stage != 2) {
            result.status = Status::invalid_stage;
            result.value.status = BootstrapContextStatus::invalid_request;
        } else {
            for (unsigned index = 0; index != 8; ++index)
                for (unsigned byte = 0; byte != 4; ++byte)
                    words[index] |= std::uint32_t(material[index * 4 + byte]) << (byte * 8);
            result.value = contribution::derive(words, routing_tag, point);
            result.status = result.value.status == BootstrapContextStatus::ok ? Status::ok : Status::derivation_failed;
            if (result.status == Status::ok) {
                result.observation = snapshot.check().error;
                if (result.observation.code != measurement::observer::Status::ok) {
                    result.status = Status::observation_failed;
                    result.value = {BootstrapContextStatus::unavailable, 0};
                }
            }
        }
    }
    PYOBF_NATIVE_ERASE(words, sizeof(words));
    PYOBF_NATIVE_ERASE(material, sizeof(material));
    return result;
}
}
