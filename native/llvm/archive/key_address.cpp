#include "key_address.hpp"
#include "../cff/reference_routes.hpp"

#include <optional>
#include <set>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"

namespace pyobfuscator::native::archive {
namespace {

std::optional<unsigned> offset(const llvm::Value *value, const llvm::AllocaInst *frame,
                                 std::set<const llvm::Value *> &active, unsigned depth) {
    if (depth > 32 || !active.insert(value).second) return {};
    std::optional<unsigned> result;
    if (const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(value)) {
        const auto *first = gep->getNumIndices() == 2 ? llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1)) : nullptr;
        const auto *second = gep->getNumIndices() == 2 ? llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(2)) : nullptr;
        if (gep->getPointerOperand() == frame && first != nullptr && first->isZero() &&
            second != nullptr && second->getValue().ult(8)) result = static_cast<unsigned>(second->getZExtValue());
    } else if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(value)) {
        const auto *slot = llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
        bool seen = false, valid = slot != nullptr;
        if (slot != nullptr) for (const auto *user : slot->users()) {
            const auto *store = llvm::dyn_cast<llvm::StoreInst>(user);
            if (store == nullptr || store->getPointerOperand() != slot) continue;
            const auto candidate = offset(store->getValueOperand(), frame, active, depth + 1);
            if (!candidate || (seen && result != candidate)) valid = false;
            result = candidate;
            seen = true;
        }
        if (!seen || !valid) result.reset();
    }
    active.erase(value);
    return result;
}

}  // namespace

bool is_key_address(const llvm::Value *value, const llvm::AllocaInst *frame, unsigned lane) {
    std::set<const llvm::Value *> active;
    const auto found = offset(value, frame, active, 0);
    return found && *found == lane;
}

const llvm::Function *routed_callee(const llvm::CallInst &call) {
    if (const auto *function = call.getCalledFunction()) return function;
    if (const auto *function = cff::resolve_reference_target(call.getCalledOperand())) return function;
    const auto *load = llvm::dyn_cast<llvm::LoadInst>(call.getCalledOperand());
    const auto *slot = load == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
    const llvm::Function *result = nullptr;
    if (slot == nullptr || !load->isVolatile()) return nullptr;
    for (const auto *user : slot->users()) {
        const auto *store = llvm::dyn_cast<llvm::StoreInst>(user);
        if (store == nullptr || store->getPointerOperand() != slot) continue;
        const auto *function = llvm::dyn_cast<llvm::Function>(store->getValueOperand());
        if (!store->isVolatile() || function == nullptr || result != nullptr) return nullptr;
        result = function;
    }
    return result;
}

}  // namespace pyobfuscator::native::archive
