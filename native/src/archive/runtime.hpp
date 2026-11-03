#pragma once

#include <cstddef>
#include <cstdint>

#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::archive {

enum class Status : std::uint32_t {
    ready = 0,
    invalid_record = 1,
    invalid_storage = 2,
    verification_failed = 3,
    decode_failed = 4,
    binding_mismatch = 5,
    invalid_cache = 6,
};

class Cache {
public:
    constexpr Cache() noexcept = default;
    Cache(const Cache &) = delete;
    Cache &operator=(const Cache &) = delete;

private:
    platform::AtomicWord32 state_{0};
    const std::uint8_t *package_ = nullptr;
    std::size_t package_size_ = 0;
    std::uint32_t record_ = 0;
    std::uint8_t *destination_ = nullptr;
    std::size_t capacity_ = 0;

    friend Status acquire_record(const std::uint8_t *, std::size_t, std::uint32_t,
                                  std::uint8_t *, std::size_t, Cache &, const std::uint8_t *) noexcept;
};

Status acquire_record(const std::uint8_t *package, std::size_t package_size, std::uint32_t record,
                        std::uint8_t *destination, std::size_t capacity, Cache &cache,
                        const std::uint8_t *key) noexcept;
void require_record(const std::uint8_t *package, std::size_t package_size, std::uint32_t record,
                     std::uint8_t *destination, std::size_t capacity, Cache &cache,
                     const std::uint8_t *key) noexcept;

}  // namespace pyobfuscator::native::archive
