#include "indexed_locals.hpp"
#include "call_frames.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
constexpr const char *tags[]{"pyobf.local.inventory", "pyobf.local.object", "pyobf.local.table", "pyobf.local.initializer",
    "pyobf.local.pending", "pyobf.local.bound", "pyobf.local.state", "pyobf.local.state-slot", "pyobf.local.control"};

std::string verify_function(const llvm::Function &function) {
    std::map<const llvm::MDNode *, const llvm::AllocaInst *> objects;
    std::map<const llvm::MDNode *, std::set<unsigned>> routes;
    const llvm::AllocaInst *table = nullptr;
    std::set<const llvm::Instruction *> initializers;
    bool artifacts = false;
    for (const auto &block : function) for (const auto &instruction : block) {
        for (const auto *name : tags) artifacts |= instruction.getMetadata(name) != nullptr;
        if (instruction.getMetadata("pyobf.local.pending")) return "indexed local address did not bind";
        if (const auto *descriptor = instruction.getMetadata("pyobf.local.object")) {
            const auto *object = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
            const auto info = local_info(descriptor);
            if (!info || object == nullptr || !objects.emplace(descriptor, object).second ||
                info->site != instruction_provenance(instruction)) return "indexed local lost its original object identity";
        }
        if (instruction.getMetadata("pyobf.local.table")) {
            if (table != nullptr) return "indexed local table is shared or duplicated";
            table = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
            if (table == nullptr || !local_table_targets(table)) return "indexed local table is incomplete, mutable or escaping";
        }
        if (const auto *bound = instruction.getMetadata("pyobf.local.bound")) {
            const auto *descriptor = bound->getNumOperands() == 4 ? llvm::dyn_cast<llvm::MDNode>(bound->getOperand(0)) : nullptr;
            const auto route = frame_number(bound, 1);
            const auto *address = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction);
            const auto *load = address != nullptr && address->hasOneUse() ? llvm::dyn_cast<llvm::LoadInst>(*address->user_begin()) : nullptr;
            const auto *target = load == nullptr ? nullptr : resolve_local_target(load);
            if (target == nullptr || descriptor != target->getMetadata("pyobf.local.object") || !route ||
                !routes[descriptor].insert(*route).second) return "indexed local route lost its actual object/index/state graph";
        }
    }
    const auto *inventory = function.getMetadata("pyobf.local.inventory");
    if (!artifacts && inventory == nullptr) return {};
    if (!function.hasFnAttribute("pyobf.cff.transformed")) return "indexed local owner was not transformed";
    if (objects.empty() || table == nullptr || inventory == nullptr || inventory->getNumOperands() != objects.size())
        return "indexed local object inventory is missing or inconsistent";
    std::set<const llvm::MDNode *> planned;
    for (const auto &entry : inventory->operands()) {
        const auto *descriptor = llvm::dyn_cast<llvm::MDNode>(entry);
        if (!objects.count(descriptor) || !planned.insert(descriptor).second) return "indexed local inventory has no unique owning object";
    }
    const auto targets = *local_table_targets(table);
    std::set<const llvm::AllocaInst *> stored;
    for (const auto *target : targets) if (target != nullptr) stored.insert(target);
    if (stored.size() != objects.size()) return "indexed local table does not contain every planned object";
    for (const auto *user : table->users()) {
        const auto *address = llvm::cast<llvm::GetElementPtrInst>(user);
        if (address->getMetadata("pyobf.local.initializer")) { initializers.insert(address); initializers.insert(llvm::cast<llvm::Instruction>(*address->user_begin())); }
    }
    for (const auto &[descriptor, object] : objects) {
        const auto info = *local_info(descriptor);
        if (!stored.count(object) || routes[descriptor].size() != info.routes) return "indexed local routes are missing or duplicated";
        unsigned controls = 0, stores = 0;
        for (const auto &use : object->uses()) {
            const auto *consumer = llvm::dyn_cast<llvm::Instruction>(use.getUser());
            if (consumer != nullptr && local_control_use(*consumer)) { ++controls; continue; }
            const auto *store = llvm::dyn_cast_or_null<llvm::StoreInst>(consumer);
            if (store == nullptr || store->getValueOperand() != object || !initializers.count(store))
                return "indexed local object has an unplanned direct address use";
            ++stores;
        }
        if (controls != info.controls || stores != 1) return "indexed local lifetime/initialization ownership changed";
    }
    for (const auto &block : function) for (const auto &instruction : block)
        if (instruction.getMetadata("pyobf.local.initializer") && !initializers.count(&instruction)) return "indexed local has an orphan table initializer";
    return {};
}
}  // namespace

std::string verify_indexed_locals(const llvm::Module &module) {
    for (const auto &function : module) if (const auto reason = verify_function(function); !reason.empty())
        return reason + ": " + function.getName().str();
    return {};
}

void reject_local_artifacts(const llvm::Module &module) {
    for (const auto &function : module) {
        for (const auto *name : tags) if (function.getMetadata(name)) llvm::report_fatal_error("indexed locals: private artifacts in source input");
        for (const auto &block : function) for (const auto &instruction : block)
            for (const auto *name : tags) if (instruction.getMetadata(name)) llvm::report_fatal_error("indexed locals: private artifacts in source input");
    }
    for (const auto *name : tags) if (module.getNamedMetadata(name)) llvm::report_fatal_error("indexed locals: private inventory in source input");
}

void strip_indexed_locals(llvm::Module &module) {
    for (auto &function : module) {
        for (const auto *name : tags) function.setMetadata(name, nullptr);
        for (auto &block : function) for (auto &instruction : block)
            for (const auto *name : tags) instruction.setMetadata(name, nullptr);
    }
}

}  // namespace pyobfuscator::native::cff
