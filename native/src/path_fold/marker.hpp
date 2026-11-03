#pragma once

#include <cstdint>

namespace pyobfuscator::native::path_fold {
struct Storage { alignas(4) std::uint32_t words[8]{}; };
}

// Reserved compiler interface. Keep only declarations in CFF input IR; link the
// reference implementation separately when ordinary/unselected code needs it.
extern "C" void pyobf_native_path_fold_init_v1(pyobfuscator::native::path_fold::Storage &,
                                               std::uint32_t seed) noexcept;
extern "C" void pyobf_native_path_fold_step_v1(pyobfuscator::native::path_fold::Storage &,
                                               std::uint32_t tag, std::uint32_t word) noexcept;
