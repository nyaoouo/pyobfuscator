#pragma once

#include "bootstrap_context.hpp"

#include <cstdint>

namespace pyobfuscator::native::contribution {

struct Site {
    std::uint32_t domain, function, site, source, current;
};

struct Result {
    BootstrapContextStatus status = BootstrapContextStatus::unavailable;
    std::uint32_t word = 0;
};

// The caller retains its consuming module through return. Required provider lifetime
// is retained by the synchronous owned-context call; no raw context/key value is returned.
Result request(const BootstrapContextLease &, std::uint32_t routing_tag, const Site &) noexcept;

// Provider-side helper. Its private eight words must remain immutable through the call.
// The normalization reserves zero for failure; this is local binding, not device authority.
Result derive(const std::uint32_t (&private_words)[8], std::uint32_t routing_tag, const Site &) noexcept;

}  // namespace pyobfuscator::native::contribution
