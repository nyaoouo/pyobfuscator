#include "buffer.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP TransientBuffer::TransientBuffer(std::size_t length, bool sensitive) noexcept
    : bytes(static_cast<std::uint8_t *>(PYOBF_NATIVE_ALLOCATE(length))), length(length), sensitive(sensitive) {}

PYOBF_NATIVE_CFF_BOOTSTRAP TransientBuffer::~TransientBuffer() { reset(); }

PYOBF_NATIVE_CFF_BOOTSTRAP void TransientBuffer::reset() noexcept {
    if (bytes != nullptr && sensitive) PYOBF_NATIVE_ERASE(bytes, length);
    PYOBF_NATIVE_RELEASE(bytes);
    bytes = nullptr;
}

}  // namespace pyobfuscator::native::demo
