#include "empty_plan.hpp"
#include "bindings.hpp"
#include "metadata.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::archive {
namespace {

void empty_contents(const llvm::Module &module, bool prepared) {
    const auto *sources = module.getNamedMetadata("pyobf.archive.sources");
    if (sources == nullptr || sources->getNumOperands() != 0)
        invalid_binding("empty plan has a nonempty or missing source inventory");
    for (const auto &metadata : module.named_metadata()) {
        const auto name = metadata.getName();
        if (!name.starts_with("pyobf.archive.")) continue;
        if (name == "pyobf.archive.sources") continue;
        if (!prepared && (name == "pyobf.archive.pending" || name == "pyobf.archive.records")) continue;
        if (prepared && (name == "pyobf.archive.prepared" || name == "pyobf.archive.empty")) continue;
        invalid_binding("empty plan has unexplained archive metadata");
    }
    for (const auto &value : module.global_values())
        if (value.getName().starts_with("__pyobf_archive_"))
            invalid_binding("empty plan retains an archive object or gate");
    for (const auto &function : module) {
        for (const auto name : {"pyobf.archive.pending", "pyobf.archive.planned", "pyobf.archive.wrapper"})
            if (function.hasFnAttribute(name)) invalid_binding("empty plan retains an archive function");
        for (const auto &block : function) for (const auto &instruction : block)
            for (const auto &entry : {"pyobf.archive.key-slot", "pyobf.archive.key-clear", "pyobf.archive.gate",
                    "pyobf.archive.materialized", "pyobf.archive.key-material", "pyobf.archive.key-bound"})
                if (instruction.getMetadata(entry) != nullptr)
                    invalid_binding("empty plan retains an archive key or acquisition");
    }
}

bool empty_flag(const llvm::Module &module, llvm::StringRef name) {
    const auto *flag = module.getNamedMetadata(name);
    return flag != nullptr && flag->getNumOperands() == 1 && flag->getOperand(0)->getNumOperands() == 0;
}

}  // namespace

void materialize_empty_plan(llvm::Module &module, const Bindings &bindings) {
    if (!bindings.records.empty() || bindings.archive_id != std::string(32, '0') ||
        bindings.package_hash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        invalid_binding("empty plan requires canonical no-pool bindings");
    empty_contents(module, false);
    module.eraseNamedMetadata(module.getNamedMetadata("pyobf.archive.pending"));
    module.eraseNamedMetadata(module.getNamedMetadata("pyobf.archive.records"));
    for (const auto name : {"pyobf.archive.prepared", "pyobf.archive.empty"})
        module.getOrInsertNamedMetadata(name)->addOperand(llvm::MDNode::get(module.getContext(), {}));
}

void verify_empty_prepared(const llvm::Module &module) {
    if (!empty_flag(module, "pyobf.archive.prepared") || !empty_flag(module, "pyobf.archive.empty"))
        invalid_binding("empty compiler handoff has invalid phase flags");
    empty_contents(module, true);
}

}  // namespace pyobfuscator::native::archive
