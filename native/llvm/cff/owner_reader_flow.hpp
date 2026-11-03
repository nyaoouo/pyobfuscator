#pragma once

#include <cstdint>
#include <string>

namespace llvm { class Function; }
namespace pyobfuscator::native::cff {
struct OwnerReaderFlow { unsigned volatile_reads = 0; std::string error; };
OwnerReaderFlow check_owner_reader_flow(const llvm::Function &, std::uint64_t key, bool capture, bool source);
}
