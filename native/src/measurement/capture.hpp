#pragma once

#include "backend.hpp"

namespace pyobfuscator::native::measurement {

class Capture;
template<std::uint32_t Owner, std::uint64_t Binding>
Capture capture_owner(const Descriptor &, platform::CodeAddress, std::uint64_t) noexcept;

class Capture {
public:
    Capture() noexcept = default;
    Capture(const Capture &) = delete;
    Capture &operator=(const Capture &) = delete;
    Capture(Capture &&) noexcept;
    Capture &operator=(Capture &&) noexcept;
    ~Capture();
    const Data &data() const noexcept;
    void reset() noexcept;

private:
    friend Capture capture(const Descriptor &, platform::CodeAddress) noexcept;
    template<std::uint32_t Owner, std::uint64_t Binding>
    friend Capture capture_owner(const Descriptor &, platform::CodeAddress, std::uint64_t) noexcept;
    void fail(Status) noexcept;
    void take(Capture &) noexcept;
    ModuleView view_{};
    Data data_{};
};

// Raw byte acquisition only. It does not validate a reference or authorize a release.
Capture capture(const Descriptor &, platform::CodeAddress member) noexcept;

}  // namespace pyobfuscator::native::measurement
