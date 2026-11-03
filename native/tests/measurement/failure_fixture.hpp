#pragma once

#include "measurement/capture.hpp"

#include <cstddef>

namespace capture_test {
struct Faults {
    bool open = false, partial_view = false, allocation = false, read = false, hash = false;
    bool backward = false, frequency = false, close = false, reenter = false;
    unsigned clock_failure = 0;
    unsigned allocation_failure_at = 0;
    bool fixed_clock = false;
    std::uint64_t clock_ticks = 100, clock_frequency = 1000000000;
    unsigned clock_advance_at = 0;
    std::uint64_t clock_advance_to = 0;
};
struct Counters { unsigned views = 0, opens = 0, closes = 0, allocations = 0, releases = 0, reads = 0, clocks = 0, hashes = 0,
    allocation_attempts = 0; };
extern Faults faults;
extern Counters counters;
extern const pyobfuscator::native::measurement::Data *closing_data;
extern void (*on_hash)(std::uint8_t *);
extern void (*on_erased)(void *, std::size_t);
void reset_fixture();
pyobfuscator::native::measurement::Descriptor input();
bool cleared(const pyobfuscator::native::measurement::Data &);
void require(bool, const char *);
}
