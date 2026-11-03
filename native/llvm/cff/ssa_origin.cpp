#include "ssa_origin.hpp"

#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {

const llvm::Value *origin(const llvm::Value *value, std::set<const llvm::Value *> &active, unsigned depth) {
    if (depth > 32 || !active.insert(value).second) return nullptr;
    const auto *load = llvm::dyn_cast<llvm::LoadInst>(value);
    const auto *slot = load == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
    if (slot == nullptr || !load->isSimple()) { active.erase(value); return value; }
    const llvm::Value *result = nullptr;
    bool valid = slot->getAllocatedType() == load->getType() &&
        slot->getParent() == &load->getFunction()->getEntryBlock();
    const auto *count = llvm::dyn_cast<llvm::ConstantInt>(slot->getArraySize());
    valid &= count != nullptr && count->isOne();
    for (const auto *user : slot->users()) {
        if (const auto *copy = llvm::dyn_cast<llvm::LoadInst>(user)) {
            valid &= copy->isSimple() && copy->getPointerOperand() == slot && copy->getType() == load->getType();
        } else if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
            if (!store->isSimple() || store->getPointerOperand() != slot || store->getValueOperand()->getType() != load->getType()) {
                valid = false; continue;
            }
            const auto *candidate = origin(store->getValueOperand(), active, depth + 1);
            if (candidate == nullptr || (result != nullptr && result != candidate)) valid = false;
            result = candidate;
        } else valid = false;
    }
    active.erase(value);
    return valid ? result : nullptr;
}

}  // namespace

const llvm::Value *unique_spill_origin(const llvm::Value *value) {
    std::set<const llvm::Value *> active;
    return value == nullptr ? nullptr : origin(value, active, 0);
}

}  // namespace pyobfuscator::native::cff
