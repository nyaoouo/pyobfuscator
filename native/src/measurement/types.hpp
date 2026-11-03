#pragma once

#include <cstddef>
#include <cstdint>

namespace pyobfuscator::native::measurement {

enum class Status : std::uint32_t {
    ok = 0, unavailable = 1, invalid_descriptor = 2, unsupported = 3,
    allocation_failed = 4, read_failed = 5, crypto_failed = 6, clock_failed = 7
};

struct Range { std::uint32_t rva, size; };

// Private canonical-v1 input. Arrays are immutable and borrowed only through capture().
struct Descriptor {
    std::uint32_t kind, subject, owner, image_size;
    std::uint64_t preferred_base;
    const Range *ranges;
    std::uint32_t range_count;
    const std::uint32_t *fixups;
    std::uint32_t fixup_count;
};

struct Data {
    Status status = Status::unavailable;
    std::uint32_t kind = 0, subject = 0, owner = 0;
    std::uint64_t read_started = 0, read_completed = 0, frequency = 0;
    std::uint8_t digest[32]{};
};

inline constexpr std::uint32_t max_ranges = 1024, max_fixups = 65536;
inline constexpr std::size_t max_subject_bytes = 64u * 1024u * 1024u;

}  // namespace pyobfuscator::native::measurement
