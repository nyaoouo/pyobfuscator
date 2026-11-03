#pragma once

#include "runtime.hpp"

namespace pyobfuscator::native::archive {

inline constexpr std::size_t header_bytes = 40;
inline constexpr std::size_t record_bytes = 96;
inline constexpr std::size_t record_core_bytes = 40;
inline constexpr std::size_t max_record_bytes = 16 * 1024 * 1024;
inline constexpr std::size_t max_package_bytes = 64 * 1024 * 1024;

enum class Kind : std::uint32_t {
    integer = 1, binary16 = 2, bfloat16 = 3, binary32 = 4, binary64 = 5,
    x87_80 = 6, binary128 = 7, bytes = 8, code_units8 = 9, code_units16 = 10, code_units32 = 11,
};

struct RecordView {
    const std::uint8_t *header;
    const std::uint8_t *descriptor;
    const std::uint8_t *ciphertext;
    std::size_t size;
    Kind kind;
    std::uint32_t width;
    std::uint32_t alignment;
};

Status parse_record(const std::uint8_t *package, std::size_t size, std::uint32_t index,
                      RecordView &record) noexcept;
bool valid_plaintext(const RecordView &record, const std::uint8_t *plaintext) noexcept;

}  // namespace pyobfuscator::native::archive
