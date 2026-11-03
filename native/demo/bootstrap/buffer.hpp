#pragma once

#include <cstddef>
#include <cstdint>

namespace pyobfuscator::native::demo {

struct TransientBuffer {
    TransientBuffer(std::size_t length, bool sensitive) noexcept;
    TransientBuffer(const TransientBuffer &) = delete;
    TransientBuffer &operator=(const TransientBuffer &) = delete;
    ~TransientBuffer();
    void reset() noexcept;
    std::uint8_t *bytes;
    std::size_t length;
    bool sensitive;
};

}  // namespace pyobfuscator::native::demo
