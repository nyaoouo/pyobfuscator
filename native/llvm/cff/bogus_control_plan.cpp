#include "bogus_controls.hpp"
#include "state_layout.hpp"

#include <map>
#include "llvm/IR/Function.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
BogusControls::BogusControls(llvm::Function &function, const StateLayout &layout, const llvm::AllocaInst *state,
    const BogusControlPlan &plan, std::optional<std::uint32_t> literal_seed, const TransitionLayers *layers)
    : owner_(&function), state_(const_cast<llvm::AllocaInst *>(state)), layers_(layers) {
    for (const auto &site : plan) {
        auto *guard = llvm::dyn_cast_or_null<llvm::BranchInst>(site.guard);
        auto *normal = llvm::dyn_cast_or_null<llvm::BasicBlock>(site.normal);
        auto *decoy = llvm::dyn_cast_or_null<llvm::BasicBlock>(site.decoy);
        auto *work = llvm::dyn_cast_or_null<llvm::StoreInst>(site.work);
        if (guard == nullptr || guard->getFunction() != owner_ || !guard->isConditional() ||
                guard->getCondition() != site.predicate || guard->getSuccessor(0) != normal || guard->getSuccessor(1) != decoy ||
                normal == nullptr || decoy == nullptr || normal->getParent() != owner_ || decoy->getParent() != owner_ ||
                !layout.states.contains(guard->getParent()) || !layout.states.contains(normal) || !layout.states.contains(decoy) ||
                work == nullptr || work->getParent() != decoy || work->getValueOperand() != site.result ||
                llvm::pred_size(decoy) != 1 || *llvm::pred_begin(decoy) != guard->getParent()) {
            error_ = "bogus control construction changed its frozen condition, route or work"; return;
        }
        BogusControlDescription d{static_cast<std::uint32_t>(records_.size() + 1), site.component == "bogus-clones" ? 1u : 2u,
            layout.states.lookup(guard->getParent()), layout.states.lookup(normal), layout.states.lookup(decoy),
            layout.transition_salt, site.predicate_salt,
            literal_seed,
            site.provenance};
        auto *tag = describe_bogus_control(function.getContext(), d);
        llvm::cast<llvm::Instruction>(guard->getCondition())->setMetadata("pyobf.bogus.guard", tag);
        work->setMetadata("pyobf.bogus.work", tag);
        add(std::move(d), tag, guard->getCondition(), work, work->getValueOperand());
    }
    if (!records_.empty()) function.addFnAttr("pyobf.bogus.controls", std::to_string(records_.size()));
}
BogusControls::BogusControls(const llvm::Function &function, const TransitionLayers *layers)
    : owner_(&function), layers_(layers) {
    std::map<unsigned, std::pair<const llvm::Instruction *, const llvm::StoreInst *>> sites;
    std::map<unsigned, BogusControlDescription> descriptions;
    for (const auto &body : function) for (const auto &instruction : body) for (const auto *key : {"pyobf.bogus.guard", "pyobf.bogus.work"}) {
        const auto *tag = instruction.getMetadata(key); if (tag == nullptr) continue;
        const auto d = read_bogus_control(tag);
        if (!d) { error_ = "bogus control descriptor is malformed"; return; }
        auto &[predicate, work] = sites[d->id];
        if (llvm::StringRef(key) == "pyobf.bogus.guard") {
            if (predicate != nullptr) { error_ = "bogus control predicate is duplicated"; return; }
            predicate = &instruction; descriptions.emplace(d->id, *d);
        } else {
            if (work != nullptr || (work = llvm::dyn_cast<llvm::StoreInst>(&instruction)) == nullptr) {
                error_ = "bogus control work is not a unique store"; return;
            }
        }
    }
    for (const auto &[id, pair] : sites) {
        const auto [predicate, work] = pair;
        if (predicate == nullptr || work == nullptr || predicate->getMetadata("pyobf.bogus.guard") != work->getMetadata("pyobf.bogus.work")) {
            error_ = "bogus control predicate/work inventory changed"; return;
        }
        const auto *state = llvm::dyn_cast<llvm::AllocaInst>(work->getPointerOperand());
        if (state == nullptr || (state_ != nullptr && state_ != state)) { error_ = "bogus control has inconsistent state storage"; return; }
        state_ = const_cast<llvm::AllocaInst *>(state);
        add(descriptions.at(id), predicate->getMetadata("pyobf.bogus.guard"), const_cast<llvm::Instruction *>(predicate),
            const_cast<llvm::StoreInst *>(work), const_cast<llvm::Value *>(work->getValueOperand()));
    }
}
void BogusControls::add(BogusControlDescription d, const llvm::MDNode *tag, llvm::Value *predicate,
    llvm::StoreInst *work, llvm::Value *result) {
    auto model = std::make_unique<TransitionModel>(*owner_, d.state, d.predicate_salt, d.literal_seed);
    if (!model->valid()) { error_ = model->error(); return; }
    records_.push_back({std::move(d), tag, llvm::cast<llvm::Instruction>(predicate)->getParent(), work->getParent(),
        predicate, result, work, std::move(model)});
}
}
