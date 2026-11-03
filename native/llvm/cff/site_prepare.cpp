#include "site_report.hpp"

#include "site_provenance.hpp"
#include "region_scope.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

CfgOrigins &SiteCoverage::origins() { return origins_; }
const CfgOrigins &SiteCoverage::origins() const { return origins_; }

void SiteCoverage::freeze_prepared_sites(llvm::Function &function, llvm::ArrayRef<const llvm::BasicBlock *> excluded) {
    prepared_sites_.clear();
    for (auto &block : function) {
        if (recipe_.region_scope && !recipe_.region_scope->contains(block)) continue;
        if (llvm::is_contained(excluded, &block)) continue;
        if (&block == &function.getEntryBlock() || origins_.get(block) == BlockRole::decoy) continue;
        auto *branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
        if (branch == nullptr) continue;
        ensure_generated_provenance(*branch, generated_);
        prepared_sites_.push_back(branch);
    }
}

const std::vector<llvm::Instruction *> &SiteCoverage::prepared_sites() const { return prepared_sites_; }

bool SiteCoverage::needs_site(llvm::StringRef component, const llvm::Instruction &instruction) const {
    const auto found = positions_.find(instruction_site_id(instruction, component, 0));
    return found != positions_.end() && sites_[found->second].status == "eligible";
}

bool SiteCoverage::can_plan_site(llvm::StringRef component, const llvm::Instruction &instruction) const {
    const auto found = positions_.find(instruction_site_id(instruction, component, 0));
    return found == positions_.end() || sites_[found->second].status == "eligible";
}

void SiteCoverage::plan_site(llvm::StringRef component, llvm::Instruction &instruction) {
    ensure_site(component, instruction, 0);
}

void SiteCoverage::reject_site(llvm::StringRef component, llvm::Instruction &instruction,
                                 llvm::StringRef reason) {
    auto &site = sites_[ensure_site(component, instruction, 0)];
    site.status = "unsupported";
    site.reason = reason.str();
}

void SiteCoverage::candidate_total(llvm::StringRef component, unsigned count) {
    candidate_totals_[component.str()] = count;
}

void SiteCoverage::preparation_metric(llvm::StringRef component, llvm::StringRef name, unsigned count) {
    preparation_metrics_[component.str()][name.str()] = count;
}

void SiteCoverage::record_donor(llvm::StringRef component, llvm::Instruction &instruction,
                                llvm::ArrayRef<llvm::Instruction *> sources) {
    auto &site = sites_[ensure_site(component, instruction, 0)];
    for (const auto *source : sources) site.donor_ids.push_back(instruction_provenance(*source));
}

void SiteCoverage::record_type(llvm::StringRef component, llvm::StringRef type) {
    ++applied_types_[component.str()][type.str()];
}

BlockRole SiteCoverage::transition_role(const llvm::Instruction &instruction) const {
    if (instruction.getMetadata("pyobf.cff.routing-edge") != nullptr) return BlockRole::routing;
    return origins_.get(*instruction.getParent());
}

void SiteCoverage::record_transition(const llvm::Instruction &instruction) {
    ++transition_sites;
    ++transition_roles_[role_name(transition_role(instruction))];
}

void SiteCoverage::capture_body_roles(llvm::ArrayRef<llvm::BasicBlock *> bodies) {
    body_roles_.clear();
    decoy_blocks = 0;
    for (const auto *body : bodies) {
        const auto role = origins_.get(*body);
        ++body_roles_[role_name(role)];
        decoy_blocks += role == BlockRole::decoy;
    }
}

}  // namespace pyobfuscator::native::cff
