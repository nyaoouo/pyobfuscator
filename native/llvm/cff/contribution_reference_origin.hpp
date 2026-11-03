#pragma once

#include <optional>

#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"

namespace pyobfuscator::native::cff {
// Schema4 admits only caller-held argument references (including a single
// immutable entry spill). This gives the standalone IR proof a numeric origin
// independent of local-value metadata, which LLVM does not permit here.
inline std::optional<unsigned> contribution_reference_argument(llvm::Value *value, llvm::Function &function) {
    if (auto *argument = llvm::dyn_cast<llvm::Argument>(value))
        return argument->getParent() == &function ? std::optional<unsigned>{argument->getArgNo()} : std::nullopt;
    auto *read = llvm::dyn_cast<llvm::LoadInst>(value);
    auto *slot = read == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(read->getPointerOperand());
    if (read == nullptr || !read->isSimple() || slot == nullptr || slot->getParent() != &function.getEntryBlock() ||
            !slot->getAllocatedType()->isPointerTy()) return std::nullopt;
    llvm::StoreInst *initial = nullptr;
    for (auto *user : slot->users()) {
        if (auto *load = llvm::dyn_cast<llvm::LoadInst>(user); load != nullptr &&
                load->getPointerOperand() == slot && load->isSimple()) continue;
        if (auto *write = llvm::dyn_cast<llvm::StoreInst>(user); write != nullptr &&
                write->getPointerOperand() == slot && write->isSimple()) {
            if (initial != nullptr) return std::nullopt;
            initial = write; continue;
        }
        if (auto *intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(user); intrinsic != nullptr &&
                (intrinsic->getIntrinsicID() == llvm::Intrinsic::lifetime_start ||
                    intrinsic->getIntrinsicID() == llvm::Intrinsic::lifetime_end)) continue;
        return std::nullopt;
    }
    if (initial == nullptr || !llvm::DominatorTree(function).dominates(initial, read)) return std::nullopt;
    auto *argument = llvm::dyn_cast<llvm::Argument>(initial->getValueOperand());
    return argument != nullptr && argument->getParent() == &function ?
        std::optional<unsigned>{argument->getArgNo()} : std::nullopt;
}
}
