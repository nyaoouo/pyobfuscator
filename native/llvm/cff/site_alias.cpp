#include "site_report.hpp"

#include "site_provenance.hpp"
#include "site_alias_graph.hpp"

#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

unsigned SiteCoverage::ensure_site(llvm::StringRef component, llvm::Instruction &instruction,
                                    unsigned operand) {
    ensure_generated_provenance(instruction, generated_);
    const auto id = instruction_site_id(instruction, component, operand);
    if (const auto found = positions_.find(id); found != positions_.end()) return found->second;
    SiteRecord record{};
    record.id = id;
    record.component = component.str();
    record.status = "eligible";
    record.origin = "generated";
    record.block = instruction.getParent()->getName().str();
    record.operand = operand;
    const auto index = static_cast<unsigned>(sites_.size());
    positions_.emplace(id, index);
    sites_.push_back(std::move(record));
    return index;
}

void SiteCoverage::relocate_use(llvm::StringRef component, llvm::Instruction &from,
                                 unsigned old_operand, llvm::Instruction &to, unsigned new_operand) {
    const auto source = positions_.find(instruction_site_id(from, component, old_operand));
    if (source == positions_.end() || sites_[source->second].status != "eligible") return;
    const auto source_index = source->second;
    const auto target_index = ensure_site(component, to, new_operand);
    auto &record = sites_[source_index];
    if (source_index == target_index || record.instances != 1 || sites_[target_index].instances != 1) {
        record.status = "unsupported";
        record.reason = "ambiguous normalization use relocation";
        return;
    }
    record.status = "relocated";
    record.replacement = sites_[target_index].id;
}

void SiteCoverage::coalesce_instruction(llvm::Instruction &from, llvm::Instruction &to) {
    ensure_generated_provenance(to, generated_);
    const auto original_size = sites_.size();
    for (unsigned index = 0; index < original_size; ++index) {
        if (sites_[index].id != instruction_site_id(from, sites_[index].component, sites_[index].operand))
            continue;
        if (sites_[index].status == "applied") {
            sites_[index].mapping_provenance = instruction_provenance(to);
            continue;
        }
        if (sites_[index].status != "eligible") continue;
        const auto component = sites_[index].component;
        const auto operand = sites_[index].operand;
        const auto target = ensure_site(component, to, operand);
        auto &record = sites_[index];
        if (index == target || record.instances != 1 || sites_[target].instances != 1) {
            record.status = "unsupported";
            record.reason = "ambiguous normalization site coalescing";
            continue;
        }
        record.status = "coalesced";
        record.replacement = sites_[target].id;
    }
}

const SiteRecord *SiteCoverage::alias_target(const SiteRecord &site) const {
    return resolve_site_alias(sites_, positions_, site);
}

std::string SiteCoverage::alias_failure(const SiteRecord &site) const {
    return validate_site_alias(sites_, positions_, site);
}

}  // namespace pyobfuscator::native::cff
