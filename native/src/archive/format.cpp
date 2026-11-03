#include "format.hpp"

#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::archive {
namespace {

PYOBF_NATIVE_CFF_SDK std::uint32_t read32(const std::uint8_t *bytes) noexcept {
    return std::uint32_t{bytes[0]} | (std::uint32_t{bytes[1]} << 8) |
           (std::uint32_t{bytes[2]} << 16) | (std::uint32_t{bytes[3]} << 24);
}

PYOBF_NATIVE_CFF_SDK std::uint64_t read64(const std::uint8_t *bytes) noexcept {
    return std::uint64_t{read32(bytes)} | (std::uint64_t{read32(bytes + 4)} << 32);
}

PYOBF_NATIVE_CFF_SDK bool valid_type(Kind kind, std::uint32_t width, std::size_t size,
                                     std::uint32_t order) noexcept {
    if (kind == Kind::bytes || kind == Kind::code_units8)
        return width == 8 && order == 0 && (kind == Kind::bytes || size >= 1);
    if ((order != 1 && order != 2) || order != PYOBF_NATIVE_BYTE_ORDER()) return false;
    switch (kind) {
    case Kind::integer: return width >= 1 && width <= 128 && size >= (width + 7) / 8 && size <= 16;
    case Kind::binary16: case Kind::bfloat16: return width == 16 && size == 2;
    case Kind::binary32: return width == 32 && size == 4;
    case Kind::binary64: return width == 64 && size == 8;
    case Kind::x87_80: return width == 80 && size >= 10 && size <= 16;
    case Kind::binary128: return width == 128 && size == 16;
    case Kind::code_units16: return width == 16 && size >= 2 && size % 2 == 0;
    case Kind::code_units32: return width == 32 && size >= 4 && size % 4 == 0;
    default: return false;
    }
}

}  // namespace

PYOBF_NATIVE_CFF_SDK Status parse_record(const std::uint8_t *package, std::size_t size,
                                        std::uint32_t index, RecordView &record) noexcept {
    if (package == nullptr || size < header_bytes || size > max_package_bytes) return Status::invalid_record;
    constexpr std::uint8_t magic[]{'P', 'Y', 'O', 'B', 'F', 'A', 'R', '1'};
    for (unsigned byte = 0; byte < sizeof(magic); ++byte)
        if (package[byte] != magic[byte]) return Status::invalid_record;
    const auto count = read32(package + 12);
    if (read32(package + 8) != 1 || count == 0 || count > 65536 || index >= count ||
        read64(package + 32) != size) return Status::invalid_record;
    const auto table_end = header_bytes + static_cast<std::size_t>(count) * record_bytes;
    if (table_end > size) return Status::invalid_record;
    const auto *descriptor = package + header_bytes + static_cast<std::size_t>(index) * record_bytes;
    const auto length = read64(descriptor + 16);
    const auto offset = read64(descriptor + 24);
    if (read32(descriptor) != index || read32(descriptor + 36) != 0 || length > max_record_bytes ||
        offset < table_end || offset > size || length > size - offset) return Status::invalid_record;
    const auto kind = static_cast<Kind>(read32(descriptor + 4));
    const auto width = read32(descriptor + 8);
    const auto alignment = read32(descriptor + 12);
    if (alignment == 0 || alignment > 4096 || (alignment & (alignment - 1)) != 0 ||
        !valid_type(kind, width, static_cast<std::size_t>(length), read32(descriptor + 32)))
        return Status::invalid_record;
    record = {package, descriptor, package + static_cast<std::size_t>(offset),
              static_cast<std::size_t>(length), kind, width, alignment};
    return Status::ready;
}

PYOBF_NATIVE_CFF_SDK bool valid_plaintext(const RecordView &record, const std::uint8_t *plaintext) noexcept {
    unsigned unit = 0;
    switch (record.kind) {
    case Kind::code_units8: unit = 1; break;
    case Kind::code_units16: unit = 2; break;
    case Kind::code_units32: unit = 4; break;
    default: return true;
    }
    for (unsigned index = 0; index < unit; ++index)
        if (plaintext[record.size - unit + index] != 0) return false;
    return true;
}

}  // namespace pyobfuscator::native::archive
