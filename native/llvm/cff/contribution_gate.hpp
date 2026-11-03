#pragma once

#include "recipe.hpp"
#include "transition_binding.hpp"
#include "llvm/IR/ValueHandle.h"

#include <array>

namespace pyobfuscator::native::cff {
class TransitionLayers;
class BogusControls;
void reject_contribution_artifacts(const llvm::Module &);
std::vector<InstructionSite> discover_contribution_sites(llvm::Function &, const ResolvedRecipe &);
unsigned normalize_contribution_sites(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
unsigned prepare_contribution_sites(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
bool contribution_transition_selected(const llvm::Instruction &);
llvm::Value *bind_contribution_transition(llvm::IRBuilder<> &, llvm::Value *, llvm::Value *,
    std::uint32_t, std::uint32_t, const ResolvedRecipe &);
std::string validate_contribution_gates(const llvm::Function &, const TransitionLayers * = nullptr, const BogusControls * = nullptr);
struct StateLayout;
class ContributionGateSeal : public TransitionBinding {
public:
    ContributionGateSeal(const llvm::Function &, const StateLayout &, const ResolvedRecipe &, const TransitionLayers * = nullptr,
        const BogusControls * = nullptr);
    std::string verify(const llvm::Function &) const override;
    bool covers_unconditional(const llvm::BasicBlock &, std::uint32_t state,
        std::uint32_t normal_encoded) const override;
    const llvm::Value *normal_encoded(const llvm::BasicBlock &, const llvm::Value *) const override;
    bool owns_state_read(const llvm::LoadInst &) const override;
    bool owns_state_write(const llvm::StoreInst &) const override;
private:
    struct Point {
        const llvm::Instruction *query;
        const llvm::BasicBlock *body;
        llvm::WeakTrackingVH lease;
        std::uint32_t site, state, sealed_yes, sealed_no;
        std::uint32_t normal_yes, normal_no;
        bool unconditional;
        std::uint32_t salt;
        std::array<std::uint32_t, 4> identity;
        std::string query_name;
        unsigned schema = 1;
        std::vector<std::uint32_t> group_fields;
        std::vector<llvm::WeakVH> group_queries;
        std::vector<llvm::WeakVH> group_references;
        std::vector<llvm::WeakVH> group_peer_references;
    };
    const llvm::Function *owner_;
    std::string query_name_;
    std::uint32_t transition_salt_;
    std::vector<Point> points_;
    const TransitionLayers *layers_;
    const BogusControls *controls_;
};
}
