#pragma once

#include "measured.hpp"

namespace pyobfuscator::native::release::measured::detail {
bool valid_record(const Record &) noexcept;
Status expand(const std::uint32_t (&)[8], const measurement::reference::Identity &,
    const std::uint8_t *, std::uint8_t *) noexcept;
}
