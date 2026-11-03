#pragma once

#include "recipe.hpp"
#include "cfg_origin.hpp"
#include "exceptional_origins.hpp"
#include "bogus_control_plan.hpp"

#include <map>
#include <string>
#include <vector>

namespace llvm {
class Function;
class Instruction;
}

namespace pyobfuscator::native::cff {
class ContributionEdgePlan;

struct RequestedSite {
    std::string id;
    std::string component;
};

void stamp_site_provenance(llvm::Function &function, llvm::StringRef origin);
std::vector<RequestedSite> collect_requested_sites(llvm::Function &function,
                                                   const ResolvedRecipe &recipe);
llvm::json::Array absent_site_coverage(const ResolvedRecipe &recipe,
                                       const std::vector<RequestedSite> &requests,
                                       llvm::StringRef status, llvm::StringRef reason);

struct SiteRecord {
    struct TransformedLocation {
        std::string block;
        unsigned instruction;
    };
    std::string id;
    std::string component;
    std::string status;
    std::string reason;
    std::string origin;
    std::string replacement;
    std::string mapping_provenance;
    std::string block;
    unsigned instruction;
    unsigned operand;
    std::string source;
    unsigned line;
    unsigned instances = 1;
    unsigned applied_instances = 0;
    std::vector<TransformedLocation> transformed;
    std::map<std::string, unsigned> applied_roles;
    std::vector<std::string> donor_ids;
};

class SiteCoverage {
public:
    SiteCoverage(llvm::Function &function, const ResolvedRecipe &recipe,
                 const std::vector<RequestedSite> &requests = {},
                 llvm::StringRef region_entry = {}, llvm::StringRef region_exit = {});
    void applied(llvm::StringRef component, llvm::Instruction &instruction,
                  unsigned operand = 0);
    void applied_cfg();
    void coalesce_instruction(llvm::Instruction &from, llvm::Instruction &to);
    void relocate_use(llvm::StringRef component, llvm::Instruction &from, unsigned old_operand,
                       llvm::Instruction &to, unsigned new_operand);
    void failed(llvm::StringRef reason);
    void capture_transformed_map(const llvm::Function &function);
    void capture_normalized_cfg(const llvm::Function &function);
    void freeze_prepared_sites(llvm::Function &function, llvm::ArrayRef<const llvm::BasicBlock *> excluded = {});
    const std::vector<llvm::Instruction *> &prepared_sites() const;
    bool needs_site(llvm::StringRef component, const llvm::Instruction &instruction) const;
    bool can_plan_site(llvm::StringRef component, const llvm::Instruction &instruction) const;
    void plan_site(llvm::StringRef component, llvm::Instruction &instruction);
    void reject_site(llvm::StringRef component, llvm::Instruction &instruction, llvm::StringRef reason);
    void candidate_total(llvm::StringRef component, unsigned count);
    void preparation_metric(llvm::StringRef component, llvm::StringRef name, unsigned count);
    void record_donor(llvm::StringRef component, llvm::Instruction &instruction,
                       llvm::ArrayRef<llvm::Instruction *> sources);
    void record_type(llvm::StringRef component, llvm::StringRef type);
    CfgOrigins &origins();
    ExceptionalOrigins &exceptional_origins();
    const CfgOrigins &origins() const;
    BlockRole transition_role(const llvm::Instruction &instruction) const;
    void record_transition(const llvm::Instruction &instruction);
    void capture_body_roles(llvm::ArrayRef<llvm::BasicBlock *> bodies);
    std::string required_failure(bool after_transform = false) const;
    llvm::json::Array components() const;
    llvm::json::Array private_map() const;
    llvm::json::Object totals() const;
    unsigned original_blocks = 0;
    unsigned real_edges = 0;
    unsigned real_decisions = 0;
    unsigned shape_padding = 0;
    unsigned decoy_blocks = 0;
    unsigned transition_sites = 0;
    unsigned real_splits = 0;
    unsigned deduplicated_blocks = 0;
    unsigned normalized_returns = 0;
    unsigned normalized_blocks = 0;
    unsigned normalized_edges = 0;
    unsigned normalized_decisions = 0;
    unsigned bogus_clone_blocks = 0;
    unsigned bogus_synthesis_blocks = 0;
    unsigned cloned_instructions = 0;
    std::shared_ptr<ContributionEdgePlan> contribution_edges;
    BogusControlPlan bogus_controls;

private:
    const ResolvedRecipe &recipe_;
    ExceptionalOrigins exceptional_;
    std::vector<SiteRecord> sites_;
    std::map<std::string, unsigned> positions_;
    unsigned generated_ = 0;
    CfgOrigins origins_;
    std::vector<llvm::Instruction *> prepared_sites_;
    std::map<std::string, unsigned> candidate_totals_;
    std::map<std::string, unsigned> body_roles_;
    std::map<std::string, unsigned> transition_roles_;
    std::map<std::string, std::map<std::string, unsigned>> preparation_metrics_;
    std::map<std::string, std::map<std::string, unsigned>> applied_types_;
    unsigned ensure_site(llvm::StringRef component, llvm::Instruction &instruction, unsigned operand);
    std::string alias_failure(const SiteRecord &site) const;
    const SiteRecord *alias_target(const SiteRecord &site) const;
};

}  // namespace pyobfuscator::native::cff
