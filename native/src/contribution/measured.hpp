#pragma once

#include "pyobfuscator_native/contribution.hpp"
#include "release/measured.hpp"

namespace pyobfuscator::native::contribution::measured {

enum class Status : std::uint32_t { ok, material_failed, invalid_stage, derivation_failed, observation_failed };
struct Result {
    Status status = Status::material_failed;
    contribution::Result value{};
    release::measured::Result material{};
    measurement::observer::Error observation{};
};

// Private consumer of late-bound post-release material. The record decodes32 early-fixed
// bytes, not a final-code-dependent constant. Actual stage/owner authority stays with the
// integrating loader, which retains this exact snapshot through transition consumption.
Result derive(const path_fold::Storage &, const release::Record &, const measurement::observer::Snapshot &,
    std::uint32_t routing_tag, const Site &) noexcept;
}
