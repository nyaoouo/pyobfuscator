#include "reference_internal.hpp"
#include "internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <new>

namespace pyobfuscator::native::measurement::reference::detail {

PYOBF_NATIVE_CFF_SDK std::uint32_t read32(const std::uint8_t *data) noexcept {
    std::uint32_t value = 0;
    for (unsigned index = 0; index != 4; ++index) value |= std::uint32_t(data[index]) << (index * 8);
    return value;
}
PYOBF_NATIVE_CFF_SDK std::uint64_t read64(const std::uint8_t *data) noexcept {
    return std::uint64_t(read32(data)) | (std::uint64_t(read32(data + 4)) << 32);
}

PYOBF_NATIVE_CFF_SDK Status decode_payload(const std::uint8_t *data, std::size_t size,
        const Identity &identity, Reference &result) noexcept {
    constexpr char magic[16] = "PYOBF-CODEREF1";
    if (size < header_size) return Status::invalid_record;
    for (unsigned index = 0; index != 16; ++index) if (data[index] != magic[index]) return Status::invalid_record;
    if (read32(data + 16) != 1 || read32(data + 20) != header_size || read32(data + 24) != 1)
        return Status::invalid_record;
    for (unsigned index = 96; index != 104; ++index) if (data[index]) return Status::invalid_record;
    if (read32(data + 28) != identity.kind || read32(data + 32) != identity.subject ||
            read32(data + 36) != identity.owner || read32(data + 40) != identity.stage) return Status::identity_mismatch;
    const auto ranges = read32(data + 44), fixups = read32(data + 48);
    if (ranges == 0 || ranges > max_ranges || fixups > max_fixups) return Status::invalid_descriptor;
    const auto used = header_size + std::size_t(ranges) * 8 + std::size_t(fixups) * 4;
    if (used > size) return Status::invalid_descriptor;
    for (auto index = used; index != size; ++index) if (data[index]) return Status::invalid_record;
    const auto allocated = std::size_t(ranges) * sizeof(Range) + std::size_t(fixups) * sizeof(std::uint32_t);
    result.allocation_ = PYOBF_NATIVE_ALLOCATE(allocated);
    if (result.allocation_ == nullptr) return Status::allocation_failed;
    result.allocation_size_ = allocated;
    auto *range_values = new (result.allocation_) Range[ranges];
    auto *fixup_storage = static_cast<std::uint8_t *>(result.allocation_) + std::size_t(ranges) * sizeof(Range);
    auto *fixup_values = fixups ? new (fixup_storage) std::uint32_t[fixups] : nullptr;
    for (std::uint32_t index = 0; index != ranges; ++index)
        range_values[index] = {read32(data + header_size + index * 8), read32(data + header_size + index * 8 + 4)};
    for (std::uint32_t index = 0; index != fixups; ++index)
        fixup_values[index] = read32(data + header_size + std::size_t(ranges) * 8 + index * 4);
    result.descriptor_ = {identity.kind, identity.subject, identity.owner, read32(data + 52), read64(data + 56),
        range_values, ranges, fixup_values, fixups};
    std::size_t material_size = 0;
    if (measurement::detail::validate(result.descriptor_, nullptr, material_size) != measurement::Status::ok)
        return Status::invalid_descriptor;
    for (unsigned index = 0; index != 32; ++index) result.digest_[index] = data[64 + index];
    return Status::ok;
}

}  // namespace pyobfuscator::native::measurement::reference::detail
