#pragma once

#include <cstdint>

namespace pyobfuscator::native::demo {

inline constexpr std::uint32_t decoy_handoff_version = 1;
inline constexpr std::uint32_t decoy_role = 0xdec01951u;

struct DecoyHandoff {
    std::uint32_t abi_version;
    std::uint32_t size;
    std::uint32_t role;
    std::int32_t failure;
};
static_assert(sizeof(DecoyHandoff) == 16);
using DecoyEntry = int (*)(const DecoyHandoff *, int);

}  // namespace pyobfuscator::native::demo
