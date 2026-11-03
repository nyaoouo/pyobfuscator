#include "measurement/backend.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace pyobfuscator::native::platform {

bool measurement_clock(measurement::ClockSample &result) noexcept {
    result = {};
    LARGE_INTEGER frequency{}, ticks{};
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
            !QueryPerformanceCounter(&ticks) || ticks.QuadPart < 0) return false;
    result = {static_cast<std::uint64_t>(ticks.QuadPart), static_cast<std::uint64_t>(frequency.QuadPart)};
    return true;
}

}  // namespace pyobfuscator::native::platform
