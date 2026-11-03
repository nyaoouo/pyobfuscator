#pragma once

#include "transition_binding.hpp"
#include "transition_model.hpp"

#include <map>
#include <optional>
#include <set>
#include <vector>

namespace llvm { class LLVMContext; class AllocaInst; class BranchInst; class MDNode; class StoreInst; }
namespace pyobfuscator::native::cff {
struct TransitionModelRegistration;
struct ResolvedRecipe;
struct StateLayout;
struct TransitionLayerSpec { const TransitionModelRegistration *model; std::uint32_t seed; unsigned rounds; };
struct TransitionLayerDescription {
    std::uint32_t state, salt;
    std::string provenance;
    std::vector<TransitionLayerSpec> models;
};
using TransitionLayerPlans = std::map<const llvm::BasicBlock *, TransitionLayerDescription>;
std::optional<TransitionLayerDescription> read_transition_layers(const llvm::MDNode *);
llvm::MDNode *describe_transition_layers(llvm::LLVMContext &, const TransitionLayerDescription &);
TransitionLayerPlans plan_transition_layers(const llvm::Function &, const StateLayout &, const ResolvedRecipe &);
llvm::MDNode *transition_layers_tag(const llvm::BranchInst &, const ResolvedRecipe &, std::uint32_t state, std::uint32_t salt);
bool has_transition_layers(const llvm::Function &);

class TransitionLayers : public TransitionBinding {
public:
    TransitionLayers(const llvm::Function &, const llvm::AllocaInst *, std::uint32_t salt, TransitionLayerPlans);
    explicit TransitionLayers(const llvm::Function &);
    std::string verify(const llvm::Function &) const override;
    bool covers_unconditional(const llvm::BasicBlock &, std::uint32_t, std::uint32_t) const override { return false; }
    const llvm::Value *normal_encoded(const llvm::BasicBlock &, const llvm::Value *) const override;
    bool owns_state_read(const llvm::LoadInst &) const override;
    bool at_state(const llvm::BasicBlock &, std::uint32_t) const;
    bool empty() const { return records_.empty(); }
private:
    struct Record {
        llvm::MDNode *description;
        std::uint32_t state;
        std::vector<std::unique_ptr<TransitionModel>> models;
    };
    void add(const llvm::BasicBlock &, const TransitionLayerDescription &);
    const llvm::Function *owner_;
    const llvm::AllocaInst *state_ = nullptr;
    std::uint32_t salt_ = 0;
    std::string error_;
    std::map<const llvm::BasicBlock *, Record> records_;
    mutable std::map<const llvm::BasicBlock *, std::pair<const llvm::Value *, const llvm::Value *>> values_;
    mutable std::set<const llvm::LoadInst *> reads_;
};
}
