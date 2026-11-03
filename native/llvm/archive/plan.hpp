#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "llvm/Support/JSON.h"

namespace llvm {
class Constant;
class DataLayout;
class Function;
class GlobalVariable;
class Instruction;
class Module;
}

namespace pyobfuscator::native::cff {
struct PipelineOptions;
}

namespace pyobfuscator::native::archive {

struct UseSite {
    llvm::Instruction *instruction;
    unsigned operand;
};

struct PlannedRecord {
    std::string id;
    std::string kind;
    unsigned bit_width = 0;
    unsigned alignment = 1;
    unsigned byte_order = 0;
    std::vector<std::uint8_t> bytes;
    llvm::Constant *initializer = nullptr;
    llvm::GlobalVariable *storage = nullptr;
    std::vector<UseSite> uses;
};

std::string encode_storage(llvm::Constant &constant, const llvm::DataLayout &layout,
                             PlannedRecord &record);
std::vector<PlannedRecord> analyze_uses(llvm::Module &module,
                                        const std::set<std::string> &functions,
                                        const std::set<std::string> &integer_exempt = {});
std::string closed_global_uses(llvm::GlobalVariable &global,
                                 const std::set<std::string> &functions,
                                 std::vector<UseSite> &uses);
std::set<std::string> early_functions(const llvm::Module &module);
void instrument_plan(llvm::Module &module, std::vector<PlannedRecord> &records);
llvm::json::Object private_plan(const std::vector<PlannedRecord> &records);
void create_plan(llvm::Module &module, const cff::PipelineOptions &options,
                    const std::string &output);
void reject_pending_plan(const llvm::Module &module);

}  // namespace pyobfuscator::native::archive
