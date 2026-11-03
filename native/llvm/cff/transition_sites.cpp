#include "transition_sites.hpp"

#include "site_report.hpp"
#include "site_provenance.hpp"

#include <algorithm>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_transition_sites(llvm::Function &function, unsigned limit,
                                                       std::uint32_t seed) {
    std::vector<InstructionSite> result;
    for (auto &block : function)
        if (auto *branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator()))
            result.push_back({branch, 0, {}});
    std::stable_sort(result.begin(), result.end(), [&](const auto &left, const auto &right) {
        return component_seed(seed, function.getName(), instruction_provenance(*left.instruction)) <
               component_seed(seed, function.getName(), instruction_provenance(*right.instruction));
    });
    if (result.size() > limit) result.resize(limit);
    return result;
}

std::vector<llvm::Instruction *> select_prepared_sites(SiteCoverage &coverage,
    llvm::StringRef component, unsigned limit,
    const std::function<std::string(const llvm::Instruction &)> &exclude) {
    std::vector<llvm::Instruction *> result;
    std::vector<llvm::Instruction *> candidates;
    for (auto *instruction : coverage.prepared_sites()) {
        const auto reason = exclude ? exclude(*instruction) : std::string{};
        if (reason.empty()) candidates.push_back(instruction);
        else if (coverage.needs_site(component, *instruction)) coverage.reject_site(component, *instruction, reason);
    }
    for (auto *instruction : candidates) {
        if (!coverage.needs_site(component, *instruction)) continue;
        if (result.size() < limit) result.push_back(instruction);
        else coverage.reject_site(component, *instruction, "prepared transition budget cannot fulfill original request");
    }
    std::stable_sort(candidates.begin(), candidates.end(), [&](const auto *left, const auto *right) {
        return static_cast<int>(coverage.transition_role(*left)) < static_cast<int>(coverage.transition_role(*right));
    });
    for (auto *instruction : candidates) {
        if (result.size() == limit) break;
        if (!coverage.can_plan_site(component, *instruction) ||
            std::find(result.begin(), result.end(), instruction) != result.end()) continue;
        coverage.plan_site(component, *instruction);
        result.push_back(instruction);
    }
    coverage.candidate_total(component, candidates.size());
    return result;
}

void mark_transition(llvm::Instruction &instruction, llvm::StringRef marker) {
    instruction.setMetadata(marker, llvm::MDNode::get(instruction.getContext(), {}));
}

bool transition_marked(const llvm::Instruction &instruction, llvm::StringRef marker) {
    return instruction.getMetadata(marker) != nullptr;
}

}  // namespace pyobfuscator::native::cff
