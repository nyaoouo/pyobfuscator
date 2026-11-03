#pragma once

#include "reference.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::measurement::reference::detail {

inline constexpr std::size_t header_size = 104, archive_overhead = 136;
inline constexpr std::uint32_t min_slot = 248, max_slot = 512 * 1024;
bool valid_identity(const Identity &) noexcept;
bool derive_key(const Identity &, const std::uint32_t (&)[8], std::uint8_t *) noexcept;
std::uint32_t read32(const std::uint8_t *) noexcept;
std::uint64_t read64(const std::uint8_t *) noexcept;

}
