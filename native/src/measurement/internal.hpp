#pragma once

#include "capture.hpp"

namespace pyobfuscator::native::measurement::detail {
Status validate(const Descriptor &, const ModuleView *, std::size_t &material_size) noexcept;
std::uint8_t *write_prefix(const Descriptor &, std::uint8_t *) noexcept;
Status read_material(const Descriptor &, const ModuleView &, std::uint8_t *) noexcept;
inline constexpr char domain[] = "pyobf.native.code.observation.v1";
}
