#include "transition_layers.hpp"
#include "transition_registry.hpp"
#include "recipe.hpp"
#include "transition_proof.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
TransitionLayers::TransitionLayers(const llvm::Function &function, const llvm::AllocaInst *state,
    std::uint32_t salt, TransitionLayerPlans plans) : owner_(&function), state_(state), salt_(salt) {
    for (const auto &[body, description] : plans) add(*body, description);
}
TransitionLayers::TransitionLayers(const llvm::Function &function) : owner_(&function) {
    for (const auto &body : function) for (const auto &instruction : body) {
        const auto *tag = instruction.getMetadata("pyobf.transition.layers"); if (tag == nullptr) continue;
        const auto description = read_transition_layers(tag);
        const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
        const auto *state = store == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(store->getPointerOperand());
        if (!description || state == nullptr || (state_ != nullptr && (state != state_ || salt_ != description->salt))) {
            error_ = "transition layers have malformed descriptors or inconsistent state storage"; return;
        }
        state_ = state; salt_ = description->salt; add(body, *description);
    }
}
void TransitionLayers::add(const llvm::BasicBlock &body, const TransitionLayerDescription &description) {
    if (records_.count(&body) || description.salt != salt_ || description.models.empty()) {
        error_ = "transition layers have duplicate bodies or inconsistent decoder plans"; return;
    }
    Record record{describe_transition_layers(body.getContext(), description), description.state, {}};
    for (const auto &spec : description.models) {
        Component component{}; component.name = spec.model->name; component.transition = spec.model->emit; component.transition_model = spec.model;
        ResolvedRecipe recipe; recipe.junk_rounds = spec.rounds;
        auto model = std::make_unique<TransitionModel>(*owner_, component, description.provenance, description.state, spec.seed, recipe);
        if (!model->valid()) { error_ = model->error(); return; }
        record.models.push_back(std::move(model));
    }
    records_.emplace(&body, std::move(record));
}
std::string TransitionLayers::verify(const llvm::Function &function) const {
    values_.clear(); reads_.clear();
    if (&function != owner_) return "transition layer owner changed";
    if (!error_.empty()) return error_;
    if (!records_.empty() && !valid_state_storage(state_, &function.getEntryBlock())) return "transition layer state storage changed";
    std::map<const llvm::BasicBlock *, unsigned> counts;
    for (const auto &body : function) for (const auto &instruction : body)
        if (const auto *tag = instruction.getMetadata("pyobf.transition.layers")) {
            const auto found = records_.find(&body);
            if (found == records_.end() || found->second.description != tag || !llvm::isa<llvm::StoreInst>(instruction) || ++counts[&body] != 1)
                return "transition layers differ from the frozen selection or descriptor";
        }
    decltype(values_) values;
    std::set<const llvm::LoadInst *> reads;
    for (const auto &[body, record] : records_) {
        if (counts[body] != 1) return "transition layer descriptor was removed";
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(body->getTerminator());
        const auto update = branch == nullptr || !branch->isUnconditional() ? std::optional<StateUpdate>{} :
            match_state_update(*body, state_, salt_, branch->getSuccessor(0));
        if (!update || update->store->getMetadata("pyobf.transition.layers") != record.description)
            return "transition layers are detached from the actual decoder update";
        const llvm::Value *normal = update->encoded;
        for (auto model = record.models.rbegin(); model != record.models.rend(); ++model) {
            normal = (*model)->match(normal, state_, *body, reads);
            if (normal == nullptr) return "transition layer expression or owned state reads changed";
        }
        // The normal-flow/source consumer owns all state writers. Unreachable bogus
        // bodies can have intentional effects before this decoder; a layer shape
        // cannot grant those effects normal-route or source authority.
        values.emplace(body, std::make_pair(update->encoded, normal));
    }
    values_ = std::move(values); reads_ = std::move(reads); return {};
}
const llvm::Value *TransitionLayers::normal_encoded(const llvm::BasicBlock &body, const llvm::Value *encoded) const {
    if (!records_.count(&body)) return encoded;
    const auto found = values_.find(&body);
    return found != values_.end() && found->second.first == encoded ? found->second.second : nullptr;
}
bool TransitionLayers::owns_state_read(const llvm::LoadInst &read) const { return reads_.count(&read); }
bool TransitionLayers::at_state(const llvm::BasicBlock &body, std::uint32_t state) const {
    const auto found = records_.find(&body); return found == records_.end() || found->second.state == state;
}
}
