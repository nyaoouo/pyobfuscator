#include "site_report.hpp"

#include "cff.hpp"
#include "site_provenance.hpp"
#include "region_scope.hpp"
#include "block_split.hpp"

#include <set>
#include <algorithm>

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {
namespace {

std::string provenance(const llvm::Instruction &instruction) {
    return instruction_provenance(instruction);
}

struct Candidate {
    std::string component;
    unsigned operand;
    std::string reason;
};

std::map<const llvm::Instruction *, std::vector<Candidate>> candidates(llvm::Function &function,
                                                                      const ResolvedRecipe &recipe,
                                                                      const ResolvedRecipe &archive_recipe,
                                                                      llvm::ArrayRef<RequestedSite> requests = {}) {
    std::map<const llvm::Instruction *, std::vector<Candidate>> result;
    for (const auto &component : registered_components()) {
        if (!recipe.enabled(component.name)) continue;
        // The broad scalar inventory must not exempt real archive integer requests.
        const auto &discovery_recipe = llvm::StringRef(component.name) == "constant-archive" ? archive_recipe : recipe;
        const auto sites = llvm::StringRef(component.name) == "split-blocks" ?
            discover_requested_splits(function, discovery_recipe, requests) : component.discover(function, discovery_recipe);
        for (const auto &site : sites)
            result[site.instruction].push_back({component.name, site.operand, site.reason});
    }
    return result;
}

std::string site_id(const llvm::Instruction &instruction, llvm::StringRef component,
                     unsigned operand) {
    return instruction_site_id(instruction, component, operand);
}

}  // namespace

void stamp_site_provenance(llvm::Function &function, llvm::StringRef origin) {
    unsigned sequence = 0;
    const auto domain = std::to_string(component_seed(0, function.getName(), "site"));
    for (auto &block : function) {
        for (auto &instruction : block) {
            if (provenance(instruction).empty()) {
                const auto id = origin.str() + "." + domain + "." + std::to_string(sequence);
                instruction.setMetadata("pyobf.cff.site", llvm::MDNode::get(
                    function.getContext(), llvm::MDString::get(function.getContext(), id)));
            }
            ++sequence;
        }
    }
}

std::vector<RequestedSite> collect_requested_sites(llvm::Function &function,
                                                   const ResolvedRecipe &recipe) {
    std::vector<RequestedSite> result;
    auto inventory_recipe = recipe;
    // Preserve the original inexpensive data/call inventory even when a later invocation
    // enables deeper protection. Expensive normalization planning runs only when requested.
    for (const auto name : {"cfg", "integer-literals", "internal-calls", "decoy-transitions"})
        if (!inventory_recipe.enabled(name)) inventory_recipe.components[name] = Requirement::optional;
    auto discovered = candidates(function, inventory_recipe, recipe);
    for (auto &block : function)
        for (auto &instruction : block)
            for (const auto &candidate : discovered[&instruction])
                result.push_back({site_id(instruction, candidate.component, candidate.operand),
                                  candidate.component});
    return result;
}

llvm::json::Array absent_site_coverage(const ResolvedRecipe &recipe,
                                       const std::vector<RequestedSite> &requests,
                                       llvm::StringRef status, llvm::StringRef reason) {
    llvm::json::Array result;
    for (const auto &component : registered_components()) {
        llvm::json::Object row;
        row["component"] = component.name;
        row["requirement"] = requirement_name(recipe.requirement(component.name));
        llvm::json::Array sites;
        if (recipe.enabled(component.name)) for (const auto &request : requests) {
            if (request.component != component.name) continue;
            llvm::json::Object site;
            site["id"] = request.id;
            site["status"] = status;
            site["reason"] = reason;
            site["origin"] = "request";
            sites.push_back(std::move(site));
        }
        row["requested"] = static_cast<std::int64_t>(sites.size());
        row["eligible"] = 0;
        row["applied"] = 0;
        row["unsupported"] = status == "unsupported" ? static_cast<std::int64_t>(sites.size()) : 0;
        row["optimized_away"] = status == "optimized-away" ? static_cast<std::int64_t>(sites.size()) : 0;
        row["unverified"] = 0;
        row["coalesced"] = 0;
        row["relocated"] = 0;
        row["sites"] = std::move(sites);
        row["status"] = recipe.enabled(component.name) ? status : "disabled";
        result.push_back(std::move(row));
    }
    return result;
}

SiteCoverage::SiteCoverage(llvm::Function &function, const ResolvedRecipe &recipe,
                           const std::vector<RequestedSite> &requests,
                           llvm::StringRef region_entry, llvm::StringRef region_exit)
    : recipe_(recipe), exceptional_(function) {
    auto discovered = candidates(function, recipe, recipe, requests);
    llvm::SmallPtrSet<llvm::BasicBlock *, 32> region;
    if (!region_entry.empty()) {
        llvm::BasicBlock *entry = nullptr;
        for (auto &block : function) if (block.getName() == region_entry) entry = &block;
        std::vector<llvm::BasicBlock *> pending;
        if (entry != nullptr) pending.push_back(entry);
        while (!pending.empty()) {
            auto *block = pending.back();
            pending.pop_back();
            if (block->getName() == region_exit || !region.insert(block).second) continue;
            for (auto *next : llvm::successors(block)) pending.push_back(next);
        }
    }
    bool retained_original = false;
    for (auto &block : function) {
        if (!region_entry.empty() && !region.contains(&block)) continue;
        origins_.set(block, BlockRole::real);
        ++original_blocks;
        const auto *term = block.getTerminator();
        const unsigned successor_count = recipe.coverage == "hybrid-eh" && llvm::isa<llvm::InvokeInst>(term) ?
            1 : term->getNumSuccessors();
        real_edges += successor_count;
        std::set<const llvm::BasicBlock *> destinations;
        for (unsigned index = 0; index < successor_count; ++index)
            destinations.insert(term->getSuccessor(index));
        real_decisions += destinations.size() > 1;
        normalized_edges += destinations.size();
        unsigned position = 0;
        for (auto &instruction : block) {
            retained_original |= llvm::StringRef(provenance(instruction)).starts_with("original.");
            for (const auto &candidate : discovered[&instruction]) {
                if (!recipe.enabled(candidate.component)) continue;
                SiteRecord record;
                record.id = site_id(instruction, candidate.component, candidate.operand);
                record.component = candidate.component;
                record.status = candidate.reason.empty() ? "eligible" : "unsupported";
                record.reason = candidate.reason;
                record.origin = "input";
                record.block = block.getName().str();
                record.instruction = position;
                record.operand = candidate.operand;
                const auto location = instruction.getDebugLoc();
                record.source = location ? location->getFilename().str() : std::string{};
                record.line = location ? location.getLine() : 0;
                const auto [found, inserted] = positions_.emplace(record.id, sites_.size());
                if (inserted) sites_.push_back(std::move(record));
                else ++sites_[found->second].instances;
            }
            ++position;
        }
    }
    normalized_blocks = original_blocks;
    normalized_decisions = real_decisions;
    // Exact pre-optimization absence is meaningful only with retained provenance metadata.
    // Legacy request producers without stamped output remain compatible but cannot prove it.
    if (region_entry.empty()) for (const auto &request : requests) {
        if (!recipe.enabled(request.component) || positions_.count(request.id)) continue;
        SiteRecord record{};
        record.id = request.id;
        record.component = request.component;
        record.status = retained_original ? "optimized-away" : "unverified";
        record.reason = retained_original ? "requested site did not survive ordinary optimization" :
            "pre-optimization site provenance is unavailable";
        record.origin = "request";
        positions_.emplace(record.id, sites_.size());
        sites_.push_back(std::move(record));
    }
}

void SiteCoverage::applied(llvm::StringRef component, llvm::Instruction &instruction,
                            unsigned operand) {
    auto &site = sites_[ensure_site(component, instruction, operand)];
    if (site.status == "coalesced" || site.status == "relocated") {
        site.status = "unsupported";
        site.reason = "attempted to rewrite a retired normalization site";
        return;
    }
    site.status = "applied";
    site.reason.clear();
    ++site.applied_instances;
    ++site.applied_roles[role_name(transition_role(instruction))];
}

void SiteCoverage::applied_cfg() {
    for (auto &site : sites_)
        if (site.component == "cfg" && site.status == "eligible") {
            site.status = "applied";
            site.applied_instances = site.instances;
            site.applied_roles["real"] = site.instances;
        }
}

void SiteCoverage::failed(llvm::StringRef reason) {
    for (auto &site : sites_) if (site.status == "eligible") {
        site.status = "unsupported";
        site.reason = reason.str();
    }
}

void SiteCoverage::capture_normalized_cfg(const llvm::Function &function) {
    normalized_blocks = 0;
    normalized_edges = 0;
    normalized_decisions = 0;
    for (const auto &block : function) {
        if (recipe_.region_scope && !recipe_.region_scope->contains(block)) continue;
        ++normalized_blocks;
        // Normalization can introduce owned source/frame routing boundaries. Their
        // declared role must survive this graph snapshot; unmarked blocks are real.
        std::set<const llvm::BasicBlock *> successors;
        const auto *term = block.getTerminator();
        const unsigned successor_count = recipe_.coverage == "hybrid-eh" && llvm::isa<llvm::InvokeInst>(term) ?
            1 : term->getNumSuccessors();
        for (unsigned index = 0; index < successor_count; ++index)
            successors.insert(term->getSuccessor(index));
        normalized_edges += successors.size();
        normalized_decisions += successors.size() > 1;
    }
}

void SiteCoverage::capture_transformed_map(const llvm::Function &function) {
    for (auto &site : sites_) site.transformed.clear();
    std::map<std::string, std::vector<SiteRecord::TransformedLocation>> locations;
    for (const auto &block : function) {
        unsigned position = 0;
        for (const auto &instruction : block) {
            std::set<unsigned> mapped_sites;
            if (!provenance(instruction).empty()) locations[provenance(instruction)].push_back(
                {block.getName().str(), position});
            if (!provenance(instruction).empty()) for (const auto &component : registered_components()) {
                const unsigned operands = std::max(1u, instruction.getNumOperands());
                for (unsigned operand = 0; operand < operands; ++operand) {
                    const auto found = positions_.find(site_id(instruction, component.name, operand));
                    if (found != positions_.end() && mapped_sites.insert(found->second).second)
                        sites_[found->second].transformed.push_back(
                            {block.getName().str(), position});
                }
            }
            ++position;
        }
    }
    for (auto &site : sites_)
        if (!site.mapping_provenance.empty()) site.transformed = locations[site.mapping_provenance];
    for (auto &site : sites_) {
        if (site.status == "coalesced" || site.status == "relocated") {
            const auto *target = alias_target(site);
            if (target != nullptr) site.transformed = target->transformed;
        }
    }
}

std::string SiteCoverage::required_failure(bool after_transform) const {
    for (const auto &component : registered_components()) {
        if (recipe_.requirement(component.name) != Requirement::required) continue;
        unsigned eligible = 0;
        for (const auto &site : sites_) if (site.component == component.name) {
            eligible += site.status == "eligible" || site.status == "applied" ||
                        site.status == "coalesced" || site.status == "relocated";
            if (after_transform && site.status == "eligible")
                return std::string(component.name) + " did not transform required site " + site.id;
            if (after_transform && site.status == "applied" &&
                site.applied_instances < site.instances)
                return std::string(component.name) + " missed a retained instance of " + site.id;
            if (after_transform && (site.status == "coalesced" || site.status == "relocated")) {
                if (const auto reason = alias_failure(site); !reason.empty()) return reason;
            }
            if (site.status == "unsupported" ||
                (recipe_.strict_components.count(component.name) &&
                 (site.status == "optimized-away" || site.status == "unverified")))
                return std::string(component.name) + " required site " + site.id + ": " + site.reason;
        }
        if (eligible == 0 && after_transform)
            return std::string(component.name) + " has zero eligible required sites";
    }
    return {};
}

llvm::json::Array SiteCoverage::components() const {
    llvm::json::Array result;
    for (const auto &component : registered_components()) {
        llvm::json::Object row;
        row["component"] = component.name;
        row["requirement"] = requirement_name(recipe_.requirement(component.name));
        if (const auto found = preparation_metrics_.find(component.name); found != preparation_metrics_.end()) {
            llvm::json::Object metrics;
            for (const auto &[name, count] : found->second) metrics[name] = count;
            row["preparation"] = std::move(metrics);
        }
        if (const auto found = candidate_totals_.find(component.name); found != candidate_totals_.end()) {
            row["candidate_total"] = found->second;
            row["candidate_scope"] = "frozen-pre-state-non-decoy-branches";
        }
        llvm::json::Array sites;
        unsigned eligible = 0, applied = 0, unsupported = 0, optimized = 0, unverified = 0;
        unsigned coalesced = 0, relocated = 0;
        std::map<std::string, unsigned> applied_roles;
        for (const auto &site : sites_) if (site.component == component.name) {
            eligible += (site.status == "eligible" || site.status == "applied" ||
                         site.status == "coalesced" || site.status == "relocated") ? site.instances : 0;
            applied += site.applied_instances;
            unsupported += site.status == "unsupported";
            optimized += site.status == "optimized-away";
            unverified += site.status == "unverified";
            coalesced += site.status == "coalesced";
            relocated += site.status == "relocated";
            for (const auto &[role, count] : site.applied_roles) applied_roles[role] += count;
            llvm::json::Object item;
            item["id"] = site.id;
            item["status"] = site.status;
            item["origin"] = site.origin;
            item["retained_instances"] = site.instances;
            item["applied_instances"] = site.applied_instances;
            if (!site.replacement.empty()) item["replacement"] = site.replacement;
            if (!site.reason.empty()) item["reason"] = site.reason;
            sites.push_back(std::move(item));
        }
        row["requested"] = static_cast<std::int64_t>(sites.size());
        row["eligible"] = eligible;
        row["applied"] = applied;
        row["unsupported"] = unsupported;
        row["optimized_away"] = optimized;
        row["unverified"] = unverified;
        row["coalesced"] = coalesced;
        row["relocated"] = relocated;
        llvm::json::Object roles;
        for (const auto &[role, count] : applied_roles) roles[role] = count;
        row["applied_roles"] = std::move(roles);
        llvm::json::Object types;
        if (const auto found = applied_types_.find(component.name); found != applied_types_.end())
            for (const auto &[type, count] : found->second) types[type] = count;
        row["applied_types"] = std::move(types);
        row["sites"] = std::move(sites);
        row["status"] = !recipe_.enabled(component.name) ? "disabled" :
            applied ? "applied" : eligible ? "eligible" : unsupported ? "unsupported" :
            optimized ? "optimized-away" : unverified ? "unverified" : "no-eligible-sites";
        result.push_back(std::move(row));
    }
    return result;
}

llvm::json::Array SiteCoverage::private_map() const {
    llvm::json::Array result;
    for (const auto &site : sites_) {
        llvm::json::Object row;
        row["id"] = site.id;
        row["original_block"] = site.block;
        row["instruction_index"] = site.instruction;
        row["operand_index"] = site.operand;
        row["source"] = site.source;
        row["line"] = site.line;
        if (!site.donor_ids.empty()) {
            llvm::json::Array donors;
            for (const auto &id : site.donor_ids) donors.push_back(id);
            row["donor_provenance"] = std::move(donors);
        }
        if (!site.replacement.empty()) row["replacement"] = site.replacement;
        llvm::json::Array transformed;
        for (const auto &location : site.transformed) {
            llvm::json::Object item;
            item["block"] = location.block;
            item["instruction_index"] = location.instruction;
            transformed.push_back(std::move(item));
        }
        row["transformed_ir"] = std::move(transformed);
        result.push_back(std::move(row));
    }
    return result;
}

llvm::json::Object SiteCoverage::totals() const {
    llvm::json::Object result;
    result["original_blocks"] = original_blocks;
    result["real_edges"] = real_edges;
    result["real_decisions"] = real_decisions;
    result["shape_padding"] = shape_padding;
    result["decoy_blocks"] = decoy_blocks;
    result["oracle_gates"] = 0;
    result["transition_sites"] = transition_sites;
    result["real_splits"] = real_splits;
    result["deduplicated_blocks"] = deduplicated_blocks;
    result["normalized_returns"] = normalized_returns;
    result["normalized_blocks"] = normalized_blocks;
    result["normalized_edges"] = normalized_edges;
    result["normalized_decisions"] = normalized_decisions;
    result["bogus_clone_blocks"] = bogus_clone_blocks;
    result["bogus_synthesis_blocks"] = bogus_synthesis_blocks;
    result["cloned_instructions"] = cloned_instructions;
    llvm::json::Object bodies;
    for (const auto &[role, count] : body_roles_) bodies[role] = count;
    result["body_roles"] = std::move(bodies);
    llvm::json::Object transitions;
    for (const auto &[role, count] : transition_roles_) transitions[role] = count;
    result["transition_roles"] = std::move(transitions);
    return result;
}

}  // namespace pyobfuscator::native::cff
