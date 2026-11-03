#pragma once

#include <cstddef>

namespace pyobfuscator::native::environment {

enum class Result {
    unavailable = 0,
    clear = 1,
    triggered = 2,
};

struct Observation {
    const char *name;
    Result result;
};

constexpr std::size_t max_detectors = 8;

struct Report {
    Result overall = Result::unavailable;
    Observation observations[max_detectors]{};
    std::size_t count = 0;
    bool valid = false;
};

// The selected backend owns this registry and its detector implementations.
Report inspect(const char *comma_separated_names) noexcept;

}  // namespace pyobfuscator::native::environment
