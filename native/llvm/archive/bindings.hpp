#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace llvm { class Module; class Function; class GlobalVariable; }

namespace pyobfuscator::native::archive {

struct RecordBinding {
    std::string id, wrapper;
    unsigned index, alignment;
    std::uint64_t size;
    std::array<std::uint8_t, 32> key;
};
struct Bindings {
    std::string plan_hash, package_hash, archive_id;
    std::vector<RecordBinding> records;
};
struct WrapperView {
    llvm::Function *wrapper;
    llvm::GlobalVariable *package;
    llvm::GlobalVariable *cache;
};

Bindings read_bindings(const std::string &path);
WrapperView verify_wrapper(llvm::Module &module, const RecordBinding &record,
                              const Bindings &bindings);
void verify_package(llvm::GlobalVariable &pool, const Bindings &bindings);
void materialize(llvm::Module &module, const std::string &path);

}  // namespace pyobfuscator::native::archive
