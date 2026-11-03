#include "runtime.hpp"

#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::archive {

PYOBF_NATIVE_CFF_SDK void require_record(const std::uint8_t *package, std::size_t package_size,
                                        std::uint32_t record, std::uint8_t *destination,
                                        std::size_t capacity, Cache &cache, const std::uint8_t *key) noexcept {
    const auto result = acquire_record(package, package_size, record, destination, capacity, cache, key);
    if (result != Status::ready) PYOBF_NATIVE_PROTECTION_FAILURE(static_cast<std::uint32_t>(result));
}

}  // namespace pyobfuscator::native::archive
