#pragma once

#include "path_fold/marker.hpp"
#include "release/record.hpp"

namespace pyobfuscator::native::demo {

bool expand_release_key(const path_fold::Storage &, const release::Record &, std::uint8_t *) noexcept;

}  // namespace pyobfuscator::native::demo
