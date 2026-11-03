#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace llvm { class Function; class GlobalVariable; class Module; }
namespace pyobfuscator::native::cff {
struct OwnerReaderBinding {
    std::uint32_t index = 0, owner = 0;
    std::uint64_t key = 0;
    std::string plan, symbol;
    const llvm::Function *capture = nullptr, *cache = nullptr;
    const llvm::GlobalVariable *table = nullptr;
};
std::vector<OwnerReaderBinding> collect_owner_readers(const llvm::Module &);
}
