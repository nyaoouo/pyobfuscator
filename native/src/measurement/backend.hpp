#pragma once

#include "types.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::measurement {

struct CodeSection { std::uint32_t rva = 0, size = 0, mapped_size = 0, flags = 0; };
struct ModuleView {
    platform::CodeLease lease{};
    const std::uint8_t *base = nullptr;
    std::uint64_t loaded_base = 0, header_base = 0;
    std::uint32_t image_size = 0, section_count = 0;
    CodeSection sections[96]{};
};
struct ClockSample { std::uint64_t ticks = 0, frequency = 0; };

}  // namespace pyobfuscator::native::measurement

namespace pyobfuscator::native::platform {
measurement::Status open_code_view(CodeAddress, measurement::ModuleView &) noexcept;
bool close_code_view(measurement::ModuleView &) noexcept;
const volatile std::uint8_t *code_span(const measurement::ModuleView &, std::uint32_t rva,
    std::uint32_t size) noexcept;
bool measurement_clock(measurement::ClockSample &) noexcept;
}

#define PYOBF_NATIVE_OPEN_CODE_VIEW(...) ::pyobfuscator::native::platform::open_code_view(__VA_ARGS__)
#define PYOBF_NATIVE_CLOSE_CODE_VIEW(...) ::pyobfuscator::native::platform::close_code_view(__VA_ARGS__)
#define PYOBF_NATIVE_CODE_SPAN(...) ::pyobfuscator::native::platform::code_span(__VA_ARGS__)
#define PYOBF_NATIVE_MEASUREMENT_CLOCK(...) ::pyobfuscator::native::platform::measurement_clock(__VA_ARGS__)
