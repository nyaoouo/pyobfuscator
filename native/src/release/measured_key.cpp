#include "measured_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::release::measured {
namespace detail {
PYOBF_NATIVE_CFF_SDK bool valid_record(const Record &record) noexcept {
    constexpr char magic[16] = "PYOBF-RELKEY-v2";
    if (record.version != 2 || record.size != sizeof(Record)) return false;
    for (unsigned index = 0; index != sizeof(magic); ++index) if (record.magic[index] != magic[index]) return false;
    for (auto byte : record.reserved) if (byte != 0) return false;
    return true;
}
}
PYOBF_NATIVE_CFF_SDK Result reconstruct(const path_fold::Storage &fold, const Record &record,
        const measurement::observer::Snapshot &snapshot, std::uint8_t *key) noexcept {
    if (key == nullptr) return {};
    Result result{Status::invalid_record};
    std::uint8_t expanded[32]{};
    if (detail::valid_record(record)) {
        auto checked = snapshot.check();
        if (checked.error.code != measurement::observer::Status::ok)
            result = {Status::observation_failed, checked.error};
        else {
            result.status = detail::expand(fold.words, snapshot.data().identity, snapshot.data().measured.digest, expanded);
            if (result.status == Status::ok) {
                // Hash callbacks and clock delay cannot turn an expired/revoked operation into a key.
                checked = snapshot.check();
                if (checked.error.code != measurement::observer::Status::ok)
                    result = {Status::observation_failed, checked.error};
                else for (unsigned index = 0; index != 32; ++index) key[index] = expanded[index] ^ record.mask[index];
            }
        }
    }
    PYOBF_NATIVE_ERASE(expanded, sizeof(expanded));
    if (result.status != Status::ok) PYOBF_NATIVE_ERASE(key, 32);
    return result;
}
}
