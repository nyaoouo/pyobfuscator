#include "bogus_controls.hpp"
#include "transition_layers.hpp"
#include "transition_proof.hpp"
#include "transition_encode.hpp"
#include "scalar_proof.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
std::string BogusControls::verify(const llvm::Function &function) const {
    verified_ = false; reads_.clear(); writes_.clear();
    if (&function != owner_) return "bogus control owner changed";
    if (!error_.empty()) return error_;
    if (layers_ != nullptr) if (const auto reason = layers_->verify(function); !reason.empty()) return reason;
    unsigned count = 0;
    if (records_.empty()) {
        if (function.hasFnAttribute("pyobf.bogus.controls")) return "bogus control inventory is empty";
        for (const auto &body : function) for (const auto &instruction : body)
            if (instruction.getMetadata("pyobf.bogus.guard") || instruction.getMetadata("pyobf.bogus.work"))
                return "bogus control has an unplanned descriptor";
        verified_ = true; return {};
    }
    if (!function.hasFnAttribute("pyobf.bogus.controls") ||
            function.getFnAttribute("pyobf.bogus.controls").getValueAsString().getAsInteger(10, count) || count != records_.size())
        return "bogus control inventory differs from its frozen plan";
    const auto *state = llvm::dyn_cast_or_null<llvm::AllocaInst>(state_);
    if (!valid_state_storage(state, &function.getEntryBlock())) return "bogus control state root changed";
    unsigned guards = 0, works = 0;
    for (const auto &body : function) for (const auto &instruction : body) for (const auto *key : {"pyobf.bogus.guard", "pyobf.bogus.work"}) {
        const auto *tag = instruction.getMetadata(key); if (tag == nullptr) continue;
        bool known = false;
        for (const auto &record : records_) {
            const auto &identity = llvm::StringRef(key) == "pyobf.bogus.guard" ? record.predicate : record.work;
            known |= identity == &instruction && tag == record.tag;
        }
        if (!known) return "bogus control descriptor or identity differs from its frozen plan";
        if (llvm::StringRef(key) == "pyobf.bogus.guard") ++guards; else ++works;
    }
    if (guards != count || works != count) return "bogus control predicate/work inventory is incomplete";
    std::set<const llvm::LoadInst *> reads;
    std::set<const llvm::StoreInst *> writes;
    for (const auto &record : records_) {
        const auto &d = record.description;
        const auto *body = llvm::dyn_cast_or_null<llvm::BasicBlock>(record.body);
        const auto *decoy = llvm::dyn_cast_or_null<llvm::BasicBlock>(record.decoy);
        const auto *predicate = llvm::dyn_cast_or_null<llvm::Instruction>(record.predicate);
        const auto *result = llvm::dyn_cast_or_null<llvm::Instruction>(record.result);
        const auto *work = llvm::dyn_cast_or_null<llvm::StoreInst>(record.work);
        if (body == nullptr || decoy == nullptr || body == decoy || body->getParent() != owner_ || decoy->getParent() != owner_ ||
                predicate == nullptr || predicate->getParent() != body || result == nullptr || result->getParent() != decoy ||
                !result->getType()->isIntegerTy(32) || result->getMetadata("pyobf.cff.bogus-result") == nullptr ||
                work == nullptr || work->getParent() != decoy || work->getValueOperand() != result ||
                work->getPointerOperand() != state || !work->isSimple() || work->getAlign() != state->getAlign() ||
                d.state == d.normal || d.state == d.decoy || d.normal == d.decoy)
            return "bogus control lost its exact condition, decoy result or owned state write";
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(body->getTerminator());
        const auto *fake_branch = llvm::dyn_cast<llvm::BranchInst>(decoy->getTerminator());
        if (branch == nullptr || fake_branch == nullptr || !branch->isUnconditional() || !fake_branch->isUnconditional() ||
                branch->getSuccessor(0) != fake_branch->getSuccessor(0)) return "bogus control decoder route changed";
        const auto update = match_state_update(*body, state, d.salt, branch->getSuccessor(0));
        const auto fake = match_state_update(*decoy, state, d.salt, branch->getSuccessor(0));
        const auto *encoded = !update ? nullptr : layers_ == nullptr ? update->encoded : layers_->normal_encoded(*body, update->encoded);
        const auto *choice = llvm::dyn_cast_or_null<llvm::SelectInst>(encoded);
        const auto *fake_encoded = !fake ? nullptr : layers_ == nullptr ? fake->encoded : layers_->normal_encoded(*decoy, fake->encoded);
        if (!update || !fake || choice == nullptr || choice->getParent() != body || choice->hasPoisonGeneratingAnnotations() ||
                choice->getCondition() != predicate || !scalar_constant(choice->getTrueValue(), encode_delta(d.state, d.normal, d.salt)) ||
                !scalar_constant(choice->getFalseValue(), encode_delta(d.state, d.decoy, d.salt)) ||
                !scalar_constant(fake_encoded, encode_delta(d.decoy, d.normal, d.salt)) || !work->comesBefore(fake->current) ||
                (layers_ != nullptr && (!layers_->at_state(*body, d.state) || !layers_->at_state(*decoy, d.decoy))))
            return "bogus control changed its frozen normal/fake choice or decoder";
        if (!record.model->match_predicate(predicate, state, *body, reads)) return "bogus control predicate or owned observations changed";
        for (const auto *controlled : {body, decoy}) for (const auto &instruction : *controlled)
            if (instruction.getMetadata("pyobf.contribution.query") || instruction.getMetadata("pyobf.contribution.source"))
                return "bogus control subdivides a protected source acquisition";
        writes.insert(work);
    }
    reads_ = std::move(reads); writes_ = std::move(writes); verified_ = true; return {};
}
const llvm::Value *BogusControls::normal_encoded(const llvm::BasicBlock &body, const llvm::Value *value) const {
    return !verified_ ? nullptr : layers_ == nullptr ? value : layers_->normal_encoded(body, value);
}
bool BogusControls::owns_state_read(const llvm::LoadInst &read) const {
    return verified_ && (reads_.count(&read) || (layers_ != nullptr && layers_->owns_state_read(read)));
}
bool BogusControls::owns_state_write(const llvm::StoreInst &write) const { return verified_ && writes_.count(&write); }
}
