#pragma once

#include <cstddef>
#include <cstdint>

namespace pyobfuscator::native::assets {

// Storage belongs to the loaded module and remains immutable for that instance.
struct ByteView {
    const std::uint8_t *data;
    std::size_t size;
};

}  // namespace pyobfuscator::native::assets
