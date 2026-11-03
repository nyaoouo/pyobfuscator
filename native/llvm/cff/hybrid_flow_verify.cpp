#include "hybrid_flow.hpp"

#include "dispatch_proof.hpp"
#include "scalar_proof.hpp"
#include "transition_encode.hpp"
#include "transition_proof.hpp"
#include "path_fold_sites.hpp"
#include "transition_binding.hpp"
#include "state_binding_proof.hpp"

#include "llvm/IR/ConstantFolder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {

bool encoded_choice(const llvm::Value *value, const llvm::BasicBlock *body,
    const llvm::Value *condition, const llvm::Constant *constant_condition, std::uint32_t yes, std::uint32_t no) {
    if (condition == nullptr) return scalar_constant(value, yes);
    if (constant_condition != nullptr) {
        auto *type = llvm::Type::getInt32Ty(body->getContext());
        if (const auto *folded = llvm::ConstantFolder().FoldSelect(const_cast<llvm::Constant *>(constant_condition),
            llvm::ConstantInt::get(type, yes), llvm::ConstantInt::get(type, no))) return value == folded;
    }
    const auto *select = llvm::dyn_cast<llvm::SelectInst>(value);
    return select != nullptr && select->getParent() == body && !select->hasPoisonGeneratingAnnotations() &&
        select->getCondition() == condition && scalar_constant(select->getTrueValue(), yes) &&
        scalar_constant(select->getFalseValue(), no);
}

}  // namespace

std::string HybridFlowSeal::verify(const llvm::Function &function, const TransitionBinding *binding) const {
    if (!error_.empty()) return error_;
    if (&function != owner_) return "hybrid flow owner changed";
    if (binding != nullptr)
        if (const auto reason = binding->verify(function); !reason.empty()) return reason;
    if (const auto reason = validate_path_fold(function); !reason.empty()) return reason;
    std::set<const llvm::BasicBlock *> blocks;
    std::set<const llvm::Instruction *> instructions;
    for (const auto &block : function) {
        blocks.insert(&block);
        for (const auto &instruction : block) instructions.insert(&instruction);
    }
    for (const auto *block : original_) if (!blocks.count(block)) return "hybrid flow lost a planned block";
    if (!instructions.count(state_) || !instructions.count(correction_) || state_ == correction_ ||
        !valid_state_storage(state_, &function.getEntryBlock()) || !valid_state_storage(correction_, &function.getEntryBlock()))
        return "hybrid flow state/correction storage changed";
    std::set<const llvm::BasicBlock *> tree;
    if (const auto reason = verify_dispatch_graph(function, state_, dispatch_, states_, original_, tree); !reason.empty()) return reason;
    if (blocks.size() != original_.size() + tree.size()) return "hybrid flow has unplanned blocks";
    const auto *entry = llvm::dyn_cast<llvm::BranchInst>(function.getEntryBlock().getTerminator());
    const auto *initial = entry == nullptr ? nullptr : llvm::dyn_cast_or_null<llvm::StoreInst>(entry->getPrevNode());
    if (entry == nullptr || !entry->isUnconditional() || entry->getSuccessor(0) != dispatch_ || initial == nullptr ||
        !initial->isSimple() || initial->getPointerOperand() != state_ || initial->getAlign() != state_->getAlign() ||
        !scalar_constant(initial->getValueOperand(), initial_)) return "hybrid flow initial state changed";
    std::set<const llvm::StoreInst *> state_writes{initial}, correction_writes;
    std::set<const llvm::LoadInst *> boundary_reads{
        llvm::cast<llvm::LoadInst>(&dispatch_->front())}, correction_reads;
    for (const auto &edge : normal_) {
        const auto update = match_state_update(*edge.body, state_, salt_, dispatch_);
        const auto yes = encode_delta(states_.at(edge.body), states_.at(edge.yes), salt_);
        const auto no = edge.no == nullptr ? yes : encode_delta(states_.at(edge.body), states_.at(edge.no), salt_);
        const bool bound = binding != nullptr && edge.condition == nullptr &&
            binding->covers_unconditional(*edge.body, states_.at(edge.body), yes);
        const auto *encoded = !update ? nullptr : binding == nullptr ? update->encoded : binding->normal_encoded(*edge.body, update->encoded);
        if (!update || encoded == nullptr || (!encoded_choice(encoded, edge.body, edge.condition, edge.constant_condition, yes, no) && !bound))
            return "hybrid flow normal correction changed its planned condition or target";
        state_writes.insert(update->store);
    }
    for (const auto &[body, terminal] : terminals_) {
        const auto *instruction = body->getTerminator();
        if (instruction != terminal.identity || instruction->getNumOperands() != terminal.operands.size())
            return "hybrid flow terminal identity changed";
        for (unsigned index = 0; index < terminal.operands.size(); ++index)
            if (instruction->getOperand(index) != terminal.operands[index] && (binding == nullptr ||
                    !binding->preserves_terminal_operand(*instruction, index, terminal.operands[index], instruction->getOperand(index))))
                return "hybrid flow terminal operand changed";
    }
    for (const auto &edge : invokes_) {
        if (!instructions.count(edge.instruction) || edge.instruction->getParent() != edge.source ||
            edge.instruction->getUnwindDest() != edge.unwind || edge.instruction->getNormalDest() != edge.gateway)
            return "hybrid flow invoke source or boundary changed";
        const auto *arm = llvm::dyn_cast_or_null<llvm::StoreInst>(edge.instruction->getPrevNode());
        if (arm == nullptr || !arm->isSimple() || arm->getPointerOperand() != correction_ ||
            arm->getAlign() != correction_->getAlign() || !scalar_constant(arm->getValueOperand(),
                encode_delta(states_.at(edge.source), states_.at(edge.continuation), salt_)))
            return "hybrid flow unwind correction is not armed by its planned source";
        correction_writes.insert(arm);
        const auto update = match_state_update(*edge.gateway, state_, salt_, dispatch_);
        if (!update || !scalar_constant(update->encoded, encode_delta(states_.at(edge.source), states_.at(edge.normal), salt_)))
            return "hybrid flow normal invoke gateway changed";
        state_writes.insert(update->store);
        boundary_reads.insert(update->current);
    }
    for (const auto &pad : pads_) {
        const auto update = match_state_update(*pad.header, state_, salt_, dispatch_);
        const auto *read = update ? llvm::dyn_cast<llvm::LoadInst>(update->encoded) : nullptr;
        if (!update || !simple_state_read(read, correction_, pad.header)) return "hybrid flow pad lost its owned unwind correction";
        state_writes.insert(update->store);
        boundary_reads.insert(update->current);
        correction_reads.insert(read);
    }
    for (const auto *user : state_->users()) {
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
            if (binding != nullptr && binding->owns_state_write(*store)) continue;
            if (!state_writes.count(store)) return "hybrid flow has an unplanned state write";
        } else if (const auto *read = llvm::dyn_cast<llvm::LoadInst>(user)) {
            if (binding != nullptr && binding->owns_state_read(*read)) continue;
            // The fold proof above owns these volatile reads and checks their exact use.
            if (read->isVolatile() && read->getMetadata("pyobf.path-fold.state") != nullptr &&
                    states_.count(read->getParent())) continue;
            if (!simple_state_read(read, state_, read->getParent()) ||
                (!states_.count(read->getParent()) && !boundary_reads.count(read))) return "hybrid flow state read escapes its planned scope";
        } else return "hybrid flow state storage escapes";
    }
    for (const auto *user : correction_->users()) {
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
            if (!correction_writes.count(store)) return "hybrid flow has an unplanned unwind correction write";
        } else if (const auto *read = llvm::dyn_cast<llvm::LoadInst>(user)) {
            if (!correction_reads.count(read)) return "hybrid flow has an unplanned unwind correction read";
        } else return "hybrid flow unwind correction escapes";
    }
    return verify_state_bindings(function, state_, states_);
}

}  // namespace pyobfuscator::native::cff
