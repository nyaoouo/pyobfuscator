#include "path_fold_sites.hpp"
#include "path_fold.hpp"

#include <array>
#include <map>
#include <optional>

#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"

namespace pyobfuscator::native::cff {
namespace {
std::optional<std::uint32_t> number(const llvm::MDNode *node, unsigned index) {
    if (node == nullptr || index >= node->getNumOperands()) return {};
    const auto *value = llvm::mdconst::dyn_extract<llvm::ConstantInt>(node->getOperand(index));
    if (value == nullptr || !value->getType()->isIntegerTy(32)) return {};
    return static_cast<std::uint32_t>(value->getZExtValue());
}
std::string identity(const llvm::MDNode *node) {
    const auto *value = node == nullptr || node->getNumOperands() == 0 ? nullptr :
        llvm::dyn_cast_or_null<llvm::MDString>(node->getOperand(0));
    return value == nullptr ? std::string{} : value->getString().str();
}
bool lane_address(const llvm::Value *pointer, const llvm::Value *storage, unsigned lane) {
    const auto *address = llvm::dyn_cast<llvm::GEPOperator>(pointer);
    const auto *index = address == nullptr || address->getNumIndices() != 1 ? nullptr :
        llvm::dyn_cast<llvm::ConstantInt>(address->getOperand(1));
    return address != nullptr && address->getSourceElementType()->isIntegerTy(32) &&
        address->getPointerOperand() == storage && index != nullptr && index->getZExtValue() == lane;
}
struct Group {
    const llvm::MDNode *descriptor = nullptr;
    std::array<const llvm::StoreInst *, 8> stores{};
    std::array<const llvm::LoadInst *, 8> before{};
};

bool same_expression(const llvm::Value *actual, const llvm::Value *reference,
                     const std::map<const llvm::Value *, const llvm::Value *> &leaves,
                     llvm::DenseSet<std::pair<const llvm::Value *, const llvm::Value *>> &visited) {
    if (const auto found = leaves.find(reference); found != leaves.end()) return actual == found->second;
    if (actual == reference) return true;
    const auto *left = llvm::dyn_cast<llvm::BinaryOperator>(actual);
    const auto *right = llvm::dyn_cast<llvm::BinaryOperator>(reference);
    if (left == nullptr || right == nullptr || left->getOpcode() != right->getOpcode() ||
            left->getType() != right->getType()) return false;
    if (const auto *operation = llvm::dyn_cast<llvm::OverflowingBinaryOperator>(left))
        if (operation->hasNoUnsignedWrap() || operation->hasNoSignedWrap()) return false;
    if (const auto *operation = llvm::dyn_cast<llvm::PossiblyExactOperator>(left))
        if (operation->isExact()) return false;
    if (!visited.insert({actual, reference}).second) return true;
    return same_expression(left->getOperand(0), right->getOperand(0), leaves, visited) &&
           same_expression(left->getOperand(1), right->getOperand(1), leaves, visited);
}
}

std::string validate_path_fold(const llvm::Function &function) {
    if (!function.hasFnAttribute("pyobf.path-fold.bound")) {
        for (const auto &body : function) for (const auto &instruction : body)
            if (instruction.getMetadata("pyobf.path-fold.bound") || instruction.getMetadata("pyobf.path-fold.state") ||
                    instruction.getMetadata("pyobf.path-fold.before")) return "path-fold lost its binding marker";
        return {};
    }
    const llvm::AllocaInst *root = nullptr;
    const llvm::LoadInst *dispatch = nullptr;
    std::map<std::string, Group> groups;
    std::map<std::string, const llvm::LoadInst *> reads;
    for (const auto &body : function) for (const auto &instruction : body) {
        if (const auto *node = instruction.getMetadata("pyobf.path-fold.state")) {
            const auto id = identity(node);
            const auto *read = llvm::dyn_cast<llvm::LoadInst>(&instruction);
            if (id.empty() || node->getNumOperands() != 1 || read == nullptr || !reads.emplace(id, read).second)
                return "path-fold current-state ownership is invalid";
        }
        if (instruction.getMetadata("pyobf.path-fold.root") != nullptr) {
            if (root != nullptr || (root = llvm::dyn_cast<llvm::AllocaInst>(&instruction)) == nullptr ||
                    !root->getAllocatedType()->isIntegerTy(32) || root->getParent() != &function.getEntryBlock())
                return "path-fold actual CFF state root is invalid";
        }
        if (instruction.getMetadata("pyobf.path-fold.dispatch") != nullptr) {
            if (dispatch != nullptr || (dispatch = llvm::dyn_cast<llvm::LoadInst>(&instruction)) == nullptr)
                return "path-fold dispatcher state read is invalid";
        }
        if (const auto *node = instruction.getMetadata("pyobf.path-fold.bound")) {
            const auto id = identity(node);
            const auto lane = number(node, 3), kind = number(node, 2);
            const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
            if (id.empty() || node->getNumOperands() != 7 || number(node, 1) != 1 || !kind || *kind > 1 ||
                    !lane || *lane >= 8 || store == nullptr || !number(node, 4) || !number(node, 5) || !number(node, 6))
                return "path-fold store descriptor is invalid";
            auto &group = groups[id];
            if (group.stores[*lane] != nullptr) return "path-fold has duplicate lane stores";
            if (group.descriptor == nullptr) group.descriptor = node;
            for (unsigned field = 0; field != 7; ++field)
                if (field != 3 && group.descriptor->getOperand(field) != node->getOperand(field))
                    return "path-fold lane descriptors disagree";
            group.stores[*lane] = store;
        }
        if (const auto *node = instruction.getMetadata("pyobf.path-fold.before")) {
            const auto id = identity(node);
            const auto lane = number(node, 1);
            const auto *load = llvm::dyn_cast<llvm::LoadInst>(&instruction);
            if (id.empty() || node->getNumOperands() != 2 || !lane || *lane >= 8 || load == nullptr ||
                    groups[id].before[*lane] != nullptr) return "path-fold snapshot descriptor is invalid";
            groups[id].before[*lane] = load;
        }
    }
    if (root == nullptr || dispatch == nullptr || dispatch->getPointerOperand() != root || groups.empty() || reads.size() != groups.size())
        return "path-fold is detached from the actual dispatcher state";
    for (const auto &[id, group] : groups) {
        const auto *node = group.descriptor;
        const auto *first = group.stores[0];
        const auto *address = first == nullptr ? nullptr : llvm::dyn_cast<llvm::GEPOperator>(first->getPointerOperand());
        const auto *storage = address == nullptr ? nullptr : address->getPointerOperand();
        const auto *current = reads.find(id) == reads.end() ? nullptr : reads.at(id);
        const bool advance = number(node, 2) == 1;
        if (storage == nullptr || current == nullptr || !current->isVolatile() ||
                !current->getType()->isIntegerTy(32) || current->getPointerOperand() != root)
            return "path-fold word does not read the actual CFF state";
        for (unsigned lane = 0; lane != 8; ++lane) {
            const auto *store = group.stores[lane];
            const auto *before = group.before[lane];
            if (store == nullptr || !store->isVolatile() || store->getAlign() < llvm::Align(4) ||
                    store->getParent() != current->getParent() || !current->comesBefore(store) ||
                    !lane_address(store->getPointerOperand(), storage, lane))
                return "path-fold eight-word store span is invalid";
            if (advance) {
                if (before == nullptr || !before->isVolatile() || !before->getType()->isIntegerTy(32) ||
                        before->getAlign() < llvm::Align(4) || before->getParent() != current->getParent() ||
                        !lane_address(before->getPointerOperand(), storage, lane))
                    return "path-fold old snapshot is invalid";
                for (const auto *output : group.stores)
                    if (output == nullptr || output->getParent() != before->getParent() || !before->comesBefore(output))
                        return "path-fold overwrites its old snapshot";
            } else if (before != nullptr) return "path-fold initialization unexpectedly reads prior state";
        }
        // Re-emit the sealed expression in a scratch function. This checks output dataflow,
        // not mathematical correctness; independent reference/execution tests cover that.
        llvm::Module scratch("path-fold-proof", function.getContext());
        auto *type = llvm::FunctionType::get(llvm::Type::getVoidTy(function.getContext()),
            {llvm::PointerType::getUnqual(function.getContext()), llvm::Type::getInt32Ty(function.getContext())}, false);
        auto *reference = llvm::Function::Create(type, llvm::Function::InternalLinkage, "reference", scratch);
        auto *block = llvm::BasicBlock::Create(function.getContext(), "entry", reference);
        llvm::IRBuilder<> builder(block);
        auto *word = emit_path_fold_word(builder, reference->getArg(1), *number(node, 5), *number(node, 6));
        auto stores = advance ? emit_path_fold_advance(builder, reference->getArg(0), builder.getInt32(*number(node, 4)), word) :
                                emit_path_fold_initialize(builder, reference->getArg(0), word);
        builder.CreateRetVoid();
        std::map<const llvm::Value *, const llvm::Value *> leaves{{reference->getArg(1), current}};
        unsigned index = 0;
        for (auto &instruction : *block) if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&instruction))
            leaves.emplace(load, group.before[index++]);
        if (index != (advance ? 8u : 0u)) return "path-fold reference snapshot is incomplete";
        llvm::DenseSet<std::pair<const llvm::Value *, const llvm::Value *>> visited;
        for (unsigned lane = 0; lane != 8; ++lane)
            if (!same_expression(group.stores[lane]->getValueOperand(), stores[lane]->getValueOperand(), leaves, visited))
                return "path-fold lane arithmetic or state dependency changed";
    }
    return {};
}

}  // namespace pyobfuscator::native::cff
