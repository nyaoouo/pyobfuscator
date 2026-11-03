#include "contribution_gate.hpp"
#include "contribution_groups.hpp"
#include "contribution_query.hpp"
#include "transition_layers.hpp"
#include "bogus_controls.hpp"
#include "scalar_proof.hpp"
#include "transition_proof.hpp"

#include <array>
#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {
namespace {
const llvm::Value *unshift(const llvm::Value *value, unsigned shift, const llvm::BasicBlock *body) {
    const auto *combined = scalar_operation(value, llvm::Instruction::Xor, body);
    const auto *right = combined == nullptr ? nullptr : scalar_operation(combined->getOperand(1), llvm::Instruction::LShr, body);
    return right != nullptr && right->getOperand(0) == combined->getOperand(0) &&
        scalar_constant(right->getOperand(1), shift) ? combined->getOperand(0) : nullptr;
}
const llvm::Value *mask_observation(const llvm::Value *value, std::uint32_t salt, const llvm::BasicBlock *body) {
    // emit_path_fold_word(observed, 0, salt) retains its final xor-zero in LLVM IR.
    const auto *identity = scalar_operation(value, llvm::Instruction::Xor, body);
    if (identity == nullptr || !scalar_constant(identity->getOperand(1), 0)) return nullptr;
    value = identity->getOperand(0);
    const auto *second = scalar_operation(unshift(value, 16, body), llvm::Instruction::Mul, body);
    if (second == nullptr || !scalar_constant(second->getOperand(1), 0x846ca68bu)) return nullptr;
    const auto *first = scalar_operation(unshift(second->getOperand(0), 15, body), llvm::Instruction::Mul, body);
    if (first == nullptr || !scalar_constant(first->getOperand(1), 0x7feb352du)) return nullptr;
    const auto *base = scalar_operation(unshift(first->getOperand(0), 16, body), llvm::Instruction::Xor, body);
    return base != nullptr && scalar_constant(base->getOperand(1), salt) ? base->getOperand(0) : nullptr;
}
}
const llvm::Value *contribution_mask_observation(const llvm::Value *value, std::uint32_t salt, const llvm::BasicBlock *body) {
    return mask_observation(value, salt, body);
}
std::string validate_contribution_gates(const llvm::Function &function, const TransitionLayers *layers, const BogusControls *controls) {
    std::optional<TransitionLayers> retained;
    if (layers == nullptr && has_transition_layers(function)) {
        retained.emplace(function);
        if (const auto reason = retained->verify(function); !reason.empty()) return "contribution " + reason;
        layers = &*retained;
    }
    std::optional<BogusControls> retained_controls;
    if (controls == nullptr && function.hasFnAttribute("pyobf.bogus.controls")) {
        retained_controls.emplace(function, layers); controls = &*retained_controls;
    }
    if (function.hasFnAttribute("pyobf.contribution.grouped")) return validate_contribution_group_gates(function, layers, controls);
    if (controls != nullptr) if (const auto reason = controls->verify(function); !reason.empty()) return reason;
    const llvm::AllocaInst *root = nullptr;
    std::vector<const llvm::CallInst *> queries;
    unsigned actual_calls = 0;
    for (const auto &body : function) for (const auto &instruction : body) {
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        const auto *target = call == nullptr ? nullptr : call->getCalledFunction();
        if (target != nullptr && reserved_contribution_query(target->getName())) ++actual_calls;
        if (instruction.getMetadata("pyobf.contribution.root")) {
            if (root != nullptr || (root = llvm::dyn_cast<llvm::AllocaInst>(&instruction)) == nullptr ||
                    !valid_state_storage(root, &function.getEntryBlock())) return "contribution state root is invalid";
        }
        if (instruction.getMetadata("pyobf.contribution.query")) {
            const auto *query = llvm::dyn_cast<llvm::CallInst>(&instruction);
            if (query == nullptr) return "contribution query is not a call";
            queries.push_back(query);
        }
    }
    if (!function.hasFnAttribute("pyobf.contribution.bound"))
        return root == nullptr && queries.empty() && actual_calls == 0 && !function.hasFnAttribute("pyobf.contribution.count") ?
            std::string{} : "contribution lost its bound function identity";
    if (root == nullptr || queries.empty()) return "contribution lost its root or queries";
    unsigned expected_calls = 0;
    if (function.getFnAttribute("pyobf.contribution.count").getValueAsString().getAsInteger(10, expected_calls) ||
            expected_calls != queries.size() || actual_calls != queries.size()) return "contribution query inventory changed";
    for (const auto *user : root->users()) {
        const auto *read = llvm::dyn_cast<llvm::LoadInst>(user);
        const auto *write = llvm::dyn_cast<llvm::StoreInst>(user);
        if (read != nullptr && layers != nullptr && layers->owns_state_read(*read)) continue;
        if (read != nullptr && controls != nullptr && controls->owns_state_read(*read)) continue;
        if (read != nullptr && read->getPointerOperand() == root && read->isSimple()) continue;
        if (write != nullptr && write->getPointerOperand() == root && write->isSimple()) continue;
        return "contribution actual state storage escaped its private loads/stores";
    }
    std::set<std::pair<std::uint32_t, std::uint32_t>> sites;
    std::set<const llvm::BasicBlock *> bodies;
    for (const auto *query : queries) {
        const auto *node = query->getMetadata("pyobf.contribution.query");
        if (node->getNumOperands() != 11) return "contribution descriptor has invalid size";
        std::array<std::uint32_t, 11> fields;
        for (unsigned index = 0; index != fields.size(); ++index) {
            const auto *value = llvm::mdconst::dyn_extract<llvm::ConstantInt>(node->getOperand(index));
            if (value == nullptr || !value->getType()->isIntegerTy(32)) return "contribution descriptor has invalid words";
            fields[index] = static_cast<std::uint32_t>(value->getZExtValue());
        }
        const auto *body = query->getParent();
        const auto *target = query->getCalledFunction();
        if (fields[0] != 1 || fields[1] == 0 || fields[6] > 1 ||
                !sites.insert({fields[1], fields[2]}).second || !bodies.insert(body).second ||
                target == nullptr || target->getName() != contribution_query_name(function) ||
                target->isVarArg() || target->getCallingConv() != llvm::CallingConv::C ||
                query->getCallingConv() != llvm::CallingConv::C || query->arg_size() != 7 ||
                !query->getType()->isIntegerTy(32) || !query->doesNotThrow() || query->hasOperandBundles() ||
                !query->getArgOperand(0)->getType()->isPointerTy() ||
                llvm::isa<llvm::ConstantPointerNull>(query->getArgOperand(0)) ||
                llvm::isa<llvm::UndefValue>(query->getArgOperand(0)) ||
                llvm::isa<llvm::PoisonValue>(query->getArgOperand(0))) return "contribution acquisition or identity changed";
        for (unsigned index = 0; index != 5; ++index) {
            const unsigned field = index < 3 ? 7 + index : index == 3 ? 1 : 10;
            if (fields[field] == 0 || !scalar_constant(query->getArgOperand(1 + index), fields[field]))
                return "contribution query public binding changed";
        }
        const auto *read = llvm::dyn_cast<llvm::LoadInst>(query->getArgOperand(6));
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(body->getTerminator());
        if (!simple_state_read(read, root, body) || !read->comesBefore(query) || branch == nullptr ||
                !branch->isUnconditional()) return "contribution query does not observe its live CFF state";
        // Existing wrapping decode proof validates the second, current-state mask. The
        // transition salt is frozen separately on the final store by the emitter below.
        const auto *store = llvm::dyn_cast_or_null<llvm::StoreInst>(branch->getPrevNode());
        const auto *salt_node = store == nullptr ? nullptr : store->getMetadata("pyobf.contribution.transition");
        const auto *salt_value = salt_node == nullptr || salt_node->getNumOperands() != 1 ? nullptr :
            llvm::mdconst::dyn_extract<llvm::ConstantInt>(salt_node->getOperand(0));
        if (salt_value == nullptr || !salt_value->getType()->isIntegerTy(32)) return "contribution lost its transition salt";
        const auto update = match_state_update(*body, root, static_cast<std::uint32_t>(salt_value->getZExtValue()), branch->getSuccessor(0));
        if (!update) return "contribution is detached from the actual wrapping state update";
        const llvm::Value *masked = layers == nullptr ? update->encoded : layers->normal_encoded(*body, update->encoded);
        if (layers != nullptr && !layers->at_state(*body, fields[2])) return "contribution layer state differs from query state";
        const llvm::Value *sealed = nullptr;
        const auto *combine = scalar_operation(masked, llvm::Instruction::Xor, body);
        if (combine == nullptr) return "contribution unsealing is absent";
        masked = combine->getOperand(0); sealed = combine->getOperand(1);
        if (mask_observation(masked, fields[3], body) != query) return "contribution does not consume the actual query result";
        if (fields[6] == 0) {
            if (fields[4] != fields[5] || !scalar_constant(sealed, fields[4])) return "contribution sealed transition changed";
        } else {
            const auto *choice = llvm::dyn_cast<llvm::SelectInst>(sealed);
            if (choice == nullptr || choice->getParent() != body ||
                    !scalar_constant(choice->getTrueValue(), fields[4]) || !scalar_constant(choice->getFalseValue(), fields[5]))
                return "contribution sealed choice changed";
        }
        for (const auto &instruction : *body) {
            if (&instruction == read) continue;
            if (instruction.comesBefore(read) || !instruction.comesBefore(store)) continue;
            if (const auto *write = llvm::dyn_cast<llvm::StoreInst>(&instruction); write != nullptr && write->getPointerOperand() == root)
                return "contribution state changed between acquisition and transition";
        }
    }
    return {};
}
}
