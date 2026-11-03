#pragma once

#include "internal.hpp"
#include "owner_inline.hpp"

namespace pyobfuscator::native::measurement::detail {
template<std::uint32_t Owner, std::uint64_t Binding>
PYOBF_NATIVE_OWNER_INLINE Status read_owned_material(const Descriptor &input, const ModuleView &view,
        std::uint8_t *output) noexcept {
    static_assert(Owner != 0 && Binding != 0);
    if (input.owner != Owner) return Status::invalid_descriptor;
    constexpr std::uint32_t chunk = 1 + Binding % 31;
    const std::uint64_t delta = view.loaded_base - input.preferred_base;
    for (std::uint32_t range = 0; range != input.range_count; ++range) {
        const auto span = input.ranges[range];
        const auto *source = PYOBF_NATIVE_CODE_SPAN(view, span.rva, span.size);
        if (source == nullptr) return Status::read_failed;
        for (std::uint32_t index = 0; index != span.size;) {
            const auto count = span.size - index < chunk ? span.size - index : chunk;
            for (std::uint32_t byte = 0; byte != count; ++byte) output[index + byte] = source[index + byte];
            index += count;
        }
        for (std::uint32_t index = 0; index != input.fixup_count; ++index) {
            const auto target = input.fixups[index];
            if (target < span.rva || std::uint64_t(target) >= std::uint64_t(span.rva) + span.size) continue;
            const auto offset = target - span.rva;
            std::uint64_t value = 0;
            for (unsigned byte = 0; byte != 8; ++byte) value |= std::uint64_t(output[offset + byte]) << (byte * 8);
            value -= delta;
            for (unsigned byte = 0; byte != 8; ++byte) output[offset + byte] = static_cast<std::uint8_t>(value >> (byte * 8));
        }
        output += span.size;
    }
    return Status::ok;
}
}
