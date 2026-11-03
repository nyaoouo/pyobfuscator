#pragma once

#include "pyobfuscator_native/contribution.hpp"

#include <cstddef>
#include <cstdint>

namespace pyobfuscator::native::contribution {

inline constexpr std::uint32_t context_protocol_version = 1;
inline constexpr std::uint32_t context_reply_tag = 0x50594331u;

struct Message {
    std::uint32_t version, size, routing_tag, reserved;
    std::uint64_t generation;
    Site point;
    std::uint32_t tail_reserved;
};
static_assert(sizeof(Site) == 20 && sizeof(Message) == 48);
static_assert(offsetof(Message, generation) == 16 && offsetof(Message, point) == 24);

}  // namespace pyobfuscator::native::contribution
