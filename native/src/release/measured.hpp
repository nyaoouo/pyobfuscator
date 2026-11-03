#pragma once

#include "record.hpp"
#include "measurement/observer.hpp"
#include "path_fold/marker.hpp"

namespace pyobfuscator::native::release::measured {
enum class Status : std::uint32_t { ok, invalid_argument, invalid_identity, invalid_record, observation_failed, crypto_failed };
struct Result {
    Status status = Status::invalid_argument;
    measurement::observer::Error observation{};
};

// Private same-build boundary. Inputs stay immutable and do not alias the32-byte output.
// The integrating loader establishes actual stage authority, not the record's stage tag.
Result reconstruct(const path_fold::Storage &, const Record &, const measurement::observer::Snapshot &,
    std::uint8_t *) noexcept;
}
