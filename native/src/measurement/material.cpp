#include "internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::detail {
namespace {
PYOBF_NATIVE_CFF_SDK void put32(std::uint8_t *output, std::uint32_t value) noexcept {
    for (unsigned byte = 0; byte != 4; ++byte) output[byte] = static_cast<std::uint8_t>(value >> (byte * 8));
}
}

PYOBF_NATIVE_CFF_SDK std::uint8_t *write_prefix(const Descriptor &input, std::uint8_t *output) noexcept {
    for (std::size_t index = 0; index != sizeof(domain); ++index) output[index] = static_cast<std::uint8_t>(domain[index]);
    output += sizeof(domain);
    const std::uint32_t fields[]{1, input.kind, input.subject, input.owner, input.range_count};
    for (auto field : fields) { put32(output, field); output += 4; }
    for (std::uint32_t index = 0; index != input.range_count; ++index) {
        put32(output, input.ranges[index].rva); put32(output + 4, input.ranges[index].size); output += 8;
    }
    return output;
}

PYOBF_NATIVE_CFF_SDK Status read_material(const Descriptor &input, const ModuleView &view,
        std::uint8_t *output) noexcept {
    const std::uint64_t delta = view.loaded_base - input.preferred_base;
    for (std::uint32_t range = 0; range != input.range_count; ++range) {
        const auto span = input.ranges[range];
        const auto *source = PYOBF_NATIVE_CODE_SPAN(view, span.rva, span.size);
        if (source == nullptr) return Status::read_failed;
        for (std::uint32_t index = 0; index != span.size; ++index) output[index] = source[index];
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

}  // namespace pyobfuscator::native::measurement::detail
