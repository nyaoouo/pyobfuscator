#include "contribution_groups.hpp"
#include "contribution_private.hpp"
#include "recipe.hpp"
#include "contribution_query.hpp"

#include <algorithm>
#include <utility>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
void report_contribution_groups(llvm::json::Object &report, const llvm::Function &function, const ResolvedRecipe &recipe) {
    llvm::json::Array sites;
    const bool mixed = recipe.contribution->schema >= 3;
    const bool source_mixed = recipe.contribution->schema == 4;
    unsigned queries = 0, owned_queries = 0, measured_queries = 0;
    for (const auto &body : function) {
        for (const auto *query : contribution_group_queries(body)) {
            ++queries;
            if (query->getCalledFunction()->getName() == contribution_group_query_name("measured-scope-v1", recipe.contribution->schema)) ++measured_queries;
            else ++owned_queries;
        }
        for (const auto &instruction : body) {
            const auto *query = llvm::dyn_cast<llvm::CallInst>(&instruction);
            if (query == nullptr || !query->getMetadata("pyobf.contribution.query")) continue;
            const auto label = llvm::cast<llvm::ConstantInt>(query->getArgOperand(4))->getZExtValue();
            const auto &group = contribution_source_group(*recipe.contribution, function.getName().str(), label);
            const auto provider = group.binding.sources.front().spec.provider;
            llvm::json::Array sources, groups;
            for (const auto &source : group.binding.sources) {
                llvm::json::Object row{
                {"id", source.spec.id}, {"word_label", source.spec.word_label}, {"encoding", source.encoding_tag},
                {"group", source.spec.group}, {"class", source.spec.provider == "measured-scope-v1" ? "referenced-evidence" : "authenticated-material"},
                {"sharing", source.spec.provider == "measured-scope-v1" ? "owner-independent" : "context-material"}, {"use", "required-binding"}};
                if (mixed) { row["provider"] = source.spec.provider; row["provider_version"] = source.spec.provider_version; }
                sources.push_back(std::move(row));
            }
            for (const auto &required : group.binding.spec.groups) groups.push_back(llvm::json::Object{
                {"id", required.id}, {"minimum", required.minimum}, {"independent_evidence", required.independent_evidence}});
            llvm::json::Object site{{"index", static_cast<std::int64_t>(sites.size())}, {"label", label},
                {"mixing_domain", group.binding.spec.mixing_domain}, {"mixing_domain_tag", group.domain},
                {"sources", std::move(sources)}, {"groups", std::move(groups)}};
            if (mixed) { site["provider"] = source_mixed ? "source-mixed-v1" : provider; site["provider_version"] = 1; }
            sites.push_back(std::move(site));
        }
    }
    if (source_mixed) {
        std::sort(sites.begin(), sites.end(), [](const llvm::json::Value &left, const llvm::json::Value &right) {
            return left.getAsObject()->getInteger("label").value() < right.getAsObject()->getInteger("label").value();
        });
        for (std::size_t index = 0; index != sites.size(); ++index)
            (*sites[index].getAsObject())["index"] = static_cast<std::int64_t>(index);
    }
    report["scheme_version"] = recipe.contribution->schema; report["query_count"] = queries;
    if (mixed) {
        report["operation_scope"] = "per-site-invocation";
        report["measured_evidence_bits"] = 256;
        report["generated_owner_independence_verified"] = false;
        report["helper_counts"] = llvm::json::Object{{"owned-context-v1", owned_queries},
            {"measured-scope-v1", measured_queries}};
        if (source_mixed) {
            report["joint_helper_contract"] = "source-mixed-context-v1";
            report["cross_provider_owner_binding_verified"] = false;
            report["individual_sites_verified"] = false;
        }
    }
    report["source_subset_contract_verified"] = report.getBoolean("ir_binding_contract_verified").value_or(false) &&
        function.hasFnAttribute("pyobf.contribution.grouped");
    report["sites"] = std::move(sites);
}
}
