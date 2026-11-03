#pragma once

#include "types.hpp"

namespace pyobfuscator::native::measurement::reference {

enum class Status : std::uint32_t {
    ok = 0, unavailable = 1, invalid_identity = 2, invalid_record = 3,
    allocation_failed = 4, crypto_failed = 5, authentication_failed = 6,
    identity_mismatch = 7, invalid_descriptor = 8
};

struct Identity {
    std::uint8_t build[16], image[16];
    std::uint32_t owner, subject, kind, stage, capacity;
};

class Reference;
namespace detail {
Status decode_payload(const std::uint8_t *, std::size_t, const Identity &, Reference &) noexcept;
}

class Reference {
public:
    Reference() noexcept = default;
    Reference(const Reference &) = delete;
    Reference &operator=(const Reference &) = delete;
    Reference(Reference &&) noexcept;
    Reference &operator=(Reference &&) noexcept;
    ~Reference();
    Status status() const noexcept;
    const Descriptor &descriptor() const noexcept;
    const std::uint8_t *expected_digest() const noexcept;
    void reset() noexcept;

private:
    friend Reference open(const std::uint8_t *, std::size_t, const Identity &, const std::uint32_t (&)[8]) noexcept;
    friend Status detail::decode_payload(const std::uint8_t *, std::size_t, const Identity &, Reference &) noexcept;
    void take(Reference &) noexcept;
    void fail(Status) noexcept;
    void *allocation_ = nullptr;
    std::size_t allocation_size_ = 0;
    Status status_ = Status::unavailable;
    Descriptor descriptor_{};
    std::uint8_t digest_[32]{};
};

// Borrowed immutable input through this call. Identity/material come from the caller.
Reference open(const std::uint8_t *, std::size_t, const Identity &, const std::uint32_t (&)[8]) noexcept;

}  // namespace pyobfuscator::native::measurement::reference
