#include "call_frames.hpp"
#include "call_preparation.hpp"

#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {

std::optional<unsigned> field(const llvm::Value *value, const llvm::Value *root, const FrameLayout &layout,
                               std::set<const llvm::Value *> &active, unsigned depth) {
    if (depth > 32 || !active.insert(value).second) return {};
    std::optional<unsigned> result;
    if (const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(value)) {
        const auto *zero = gep->getNumIndices() == 2 ? llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1)) : nullptr;
        const auto *index = gep->getNumIndices() == 2 ? llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(2)) : nullptr;
        if (gep->getPointerOperand() == root && gep->getSourceElementType() == layout.type && zero != nullptr &&
            zero->isZero() && index != nullptr && index->getValue().ult(layout.type->getNumElements()))
            result = static_cast<unsigned>(index->getZExtValue());
        else result = prepared_frame_field(*gep, root, layout);
    } else if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(value)) {
        const auto *slot = llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
        bool seen = false, valid = slot != nullptr;
        if (slot != nullptr) for (const auto *user : slot->users()) {
            if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user); store != nullptr && store->getPointerOperand() == slot) {
                const auto next = field(store->getValueOperand(), root, layout, active, depth + 1);
                if (!next || (seen && result != next)) valid = false;
                result = next;
                seen = true;
            } else if (!llvm::isa<llvm::LoadInst>(user)) valid = false;
        }
        if (!seen || !valid) result.reset();
    }
    active.erase(value);
    return result;
}

bool closed_address(const llvm::Value *value, const std::set<const llvm::Instruction *> &allowed,
                       std::set<const llvm::Value *> &seen, unsigned depth) {
    if (depth > 32 || seen.size() > 4096) return false;
    if (!seen.insert(value).second) return true;
    for (const auto *user : value->users()) {
        const auto *instruction = llvm::dyn_cast<llvm::Instruction>(user);
        if (instruction != nullptr && allowed.count(instruction)) continue;
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
            const auto *slot = llvm::dyn_cast<llvm::AllocaInst>(store->getPointerOperand());
            if (store->getValueOperand() != value || slot == nullptr || !slot->getAllocatedType()->isPointerTy()) return false;
            for (const auto *spill_user : slot->users()) {
                if (spill_user == store) continue;
                const auto *load = llvm::dyn_cast<llvm::LoadInst>(spill_user);
                if (load == nullptr || load->getPointerOperand() != slot ||
                    !closed_address(load, allowed, seen, depth + 1)) return false;
            }
        } else return false;
    }
    return true;
}

}  // namespace

bool is_frame_field(const llvm::Value *value, const llvm::Value *root, const FrameLayout &layout, unsigned index) {
    std::set<const llvm::Value *> active;
    const auto found = field(value, root, layout, active, 0);
    return found && *found == index;
}

bool closed_frame_storage(const llvm::Value *frame, const FrameLayout &layout,
                            const std::set<const llvm::Instruction *> &allowed) {
    std::set<const llvm::Value *> seen;
    for (const auto *user : frame->users()) {
        const auto *instruction = llvm::dyn_cast<llvm::Instruction>(user);
        if (instruction != nullptr && allowed.count(instruction)) continue;
        const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(user);
        if (gep == nullptr) return false;
        std::set<const llvm::Value *> active;
        if (!field(gep, frame, layout, active, 0) || !closed_address(gep, allowed, seen, 0)) return false;
    }
    return true;
}

}  // namespace pyobfuscator::native::cff
