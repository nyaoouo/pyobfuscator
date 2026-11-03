#pragma once

#include <cstddef>
#include <cstdint>

namespace pyobfuscator::native::release {

struct Record {
    char magic[16];
    std::uint32_t version;
    std::uint32_t size;
    std::uint8_t mask[32];
    std::uint8_t reserved[8];
};
static_assert(sizeof(Record) == 64 && offsetof(Record, mask) == 24);

// Only this declaration belongs in protected input. The zero initializer is a
// separate native object; its fixed data is filled after executable layout freezes.
extern const Record record;

}  // namespace pyobfuscator::native::release
