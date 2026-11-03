#include "transition_model.hpp"

#include <map>
#include <vector>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
bool TransitionModel::match_graph(const llvm::Value *actual, const llvm::Value *state_slot,
    const llvm::BasicBlock &body, const llvm::Value *&normal, std::set<const llvm::LoadInst *> &reads) const {
    if (!valid() || model_ == nullptr) return false;
    std::map<const llvm::Value *, const llvm::Value *> matched;
    std::map<const llvm::Value *, const llvm::Value *> references;
    std::vector<std::pair<const llvm::Value *, const llvm::Value *>> pending{{actual, result_}};
    std::set<const llvm::LoadInst *> observed;
    while (!pending.empty()) {
        const auto [value, reference] = pending.back(); pending.pop_back();
        if (value == nullptr || value->getType() != reference->getType()) return false;
        if (reference == model_->getArg(0)) {
            if (normal != nullptr && normal != value) return false;
            normal = value; continue;
        }
        if (reference == model_->getArg(1)) { if (value != state_slot) return false; continue; }
        if (const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(reference)) { if (value != constant) return false; continue; }
        if (const auto found = matched.find(reference); found != matched.end()) { if (found->second != value) return false; continue; }
        const auto *instruction = llvm::dyn_cast<llvm::Instruction>(value);
        const auto *expected = llvm::dyn_cast<llvm::Instruction>(reference);
        if (instruction == nullptr || instruction->getParent() != &body || expected == nullptr ||
                !instruction->isSameOperationAs(expected) || instruction->hasPoisonGeneratingAnnotations()) return false;
        // Preserve distinct observations/operations as well as repeated operand identity.
        // A one-way match otherwise admits merging the two opaque volatile reads.
        if (const auto found = references.find(value); found != references.end() && found->second != reference) return false;
        if (const auto *read = llvm::dyn_cast<llvm::LoadInst>(instruction)) observed.insert(read);
        for (unsigned index = 0; index != expected->getNumOperands(); ++index)
            pending.push_back({instruction->getOperand(index), expected->getOperand(index)});
        matched.emplace(reference, value);
        references.emplace(value, reference);
    }
    if (observed.empty() || (mode_ != Mode::identity ? normal != nullptr : normal == nullptr)) return false;
    reads.insert(observed.begin(), observed.end()); return true;
}
const llvm::Value *TransitionModel::match(const llvm::Value *actual, const llvm::Value *state_slot,
    const llvm::BasicBlock &body, std::set<const llvm::LoadInst *> &reads) const {
    const llvm::Value *normal = nullptr;
    return mode_ == Mode::identity && match_graph(actual, state_slot, body, normal, reads) ? normal : nullptr;
}
bool TransitionModel::match_predicate(const llvm::Value *actual, const llvm::Value *state_slot,
    const llvm::BasicBlock &body, std::set<const llvm::LoadInst *> &reads) const {
    const llvm::Value *normal = nullptr;
    return mode_ == Mode::predicate && match_graph(actual, state_slot, body, normal, reads);
}
bool TransitionModel::match_literal(const llvm::Value *actual, const llvm::Value *state_slot,
    const llvm::BasicBlock &body, std::set<const llvm::LoadInst *> &reads) const {
    const llvm::Value *normal = nullptr;
    return mode_ == Mode::literal && match_graph(actual, state_slot, body, normal, reads);
}
}
