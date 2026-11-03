#pragma once

#include "observer.hpp"
#include "owner_inline.hpp"

namespace pyobfuscator::native::measurement::observer {
template<std::uint32_t Owner, std::uint64_t Binding>
PYOBF_NATIVE_OWNER_INLINE bool transform_owner_cache(std::uint64_t binding, Observation &record) noexcept {
    static_assert(Owner != 0 && Binding != 0);
    if (binding != Binding || record.identity.owner != Owner || record.measured.owner != Owner ||
            record.error.code != Status::ok || record.measured.status != measurement::Status::ok) return false;
    for (unsigned index = 0; index != 32; ++index) {
        const auto mask = static_cast<std::uint8_t>((Binding >> ((index % 8) * 8)) ^
            (Owner >> ((index % 4) * 8)) ^ (0x5b + 23 * index));
        record.measured.digest[index] ^= mask;
    }
    record.instance ^= Binding ^ 0x19f4c27d613bea05ull;
    record.subject_instance ^= Binding ^ 0xc7bd65204ea9138full;
    record.epoch ^= Binding ^ 0x7e5183d6a2490cbbull;
    record.sequence ^= Binding ^ 0xb4239df06c8a571eull;
    record.measured.read_started ^= Binding ^ 0x25d9c0e847b13fa6ull;
    record.measured.read_completed ^= Binding ^ 0x964a1b7fe0c5328dull;
    record.measured.frequency ^= Binding ^ 0xf0b8156e439da2c7ull;
    return true;
}
}
