#include "pipeline.hpp"
#include "reference_routes.hpp"
#include "call_frames.hpp"
#include "call_preparation.hpp"
#include "indexed_locals.hpp"
#include "module_prepare.hpp"
#include "generated_ownership.hpp"
#include "owner_reader_contract.hpp"
#include "owner_creator_flow.hpp"
#include "frame_profile.hpp"
#include "mutation_guard.hpp"
#include "contribution_private.hpp"
#include "contribution_gate.hpp"
#include "contribution_edges.hpp"
#include "bogus_controls.hpp"
#include "../archive/plan.hpp"
#include "../archive/source_report.hpp"

#include "cff.hpp"
#include "region.hpp"
#include "region_scope.hpp"
#include "contribution_groups.hpp"
#include "owner_post_flow.hpp"
#include "owner_post_child_flow.hpp"
#include "contribution_private.hpp"
#include "site_report.hpp"
#include "hybrid_eh.hpp"

#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
void configure_region(ResolvedRecipe &recipe, llvm::Function &function, const Selection &selection) {
    const auto found = selection.regions.find(function.getName().str());
    if (found != selection.regions.end() && !function.isDeclaration())
        recipe.region_scope = std::make_shared<RegionScope>(function, found->second.entry, found->second.exit);
}

bool has_control_decision(const llvm::Function &function) {
    for (const auto &block : function) {
        const auto *term = block.getTerminator();
        if (llvm::isa<llvm::InvokeInst>(term)) continue;
        std::set<const llvm::BasicBlock *> targets;
        for (unsigned index = 0; index < term->getNumSuccessors(); ++index)
            targets.insert(term->getSuccessor(index));
        if (targets.size() > 1) return true;
    }
    return false;
}

}  // namespace

void collect_pipeline_requests(llvm::Module &module, const PipelineOptions &options) {
    reject_contribution_artifacts(module);
    reject_bogus_control_artifacts(module);
    reject_local_artifacts(module);
    reject_preparation_artifacts(module);
    reject_call_frame_artifacts(module);
    reject_reference_artifacts(module);
    archive::reject_pending_plan(module);
    if (module.getNamedMetadata("pyobf.archive.prepared") != nullptr || module.getNamedMetadata("pyobf.archive.empty") != nullptr)
        llvm::report_fatal_error("collect native archive requests before planning");
    if (options.requests_output.empty())
        llvm::report_fatal_error("native CFF request collection needs an output path");
    const auto configuration = read_recipe_configuration(options.configuration);
    const auto selection = resolve_selection(module, options, configuration);
    Requests requests;
    for (const auto &name : selection.functions) {
        auto *function = module.getFunction(name);
        const auto marker = selection.markers.find(name);
        Request request{marker == selection.markers.end() ? std::string{} : marker->second,
                        function != nullptr && !function->isDeclaration(), {}};
        if (request.defined) {
            stamp_site_provenance(*function, "original");
            auto recipe = resolve_recipe(configuration, name, request.marker,
                options.strategy, selection.deep.count(name), selection.regions.count(name), options.seed);
            configure_region(recipe, *function, selection);
            for (const auto &component : registered_components()) {
                if (!recipe.enabled(component.name) || component.retain_source == nullptr) continue;
                const CfgSeal seal(*function);
                component.retain_source(*function, recipe);
                if (const auto reason = seal.check(*function); !reason.empty())
                    llvm::report_fatal_error(llvm::StringRef("native CFF source retention: " + reason));
            }
            request.sites = collect_requested_sites(*function, recipe);
        }
        requests.emplace(name, std::move(request));
    }
    write_request_manifest(module, options.requests_output, requests);
}

void run_pipeline(llvm::Module &module, const PipelineOptions &options) {
    constexpr llvm::StringRef post_edge_owners =
        "pyobf_demo_bound_compute,pyobf_demo_protection_wrapper";
    if (!options.original_edge_owners.empty() && options.original_edge_owners != post_edge_owners)
        llvm::report_fatal_error("POST original-edge owners must be the exact canonical role pair");
    if (!options.original_edge_owners.empty() && options.original_edge_plan_input.empty())
        llvm::report_fatal_error("POST original-edge owners require a frozen exact-IR plan");
    reject_contribution_artifacts(module);
    reject_bogus_control_artifacts(module);
    reject_local_artifacts(module);
    reject_preparation_artifacts(module);
    reject_call_frame_artifacts(module);
    reject_reference_artifacts(module);
    archive::reject_pending_plan(module);
    const auto original_edge_plan_sha256 = options.original_edge_plan_input.empty() ?
        std::string{} : verify_original_edge_plan(module, options, options.original_edge_plan_input);
    const auto configuration = read_recipe_configuration(options.configuration);
    auto selection = resolve_selection(module, options, configuration);
    if (find_strategy(options.strategy) == nullptr)
        llvm::report_fatal_error(llvm::StringRef("unknown native CFF strategy: " + options.strategy));

    // Resolve every override before any selected function is instrumented.
    std::map<std::string, ResolvedRecipe> recipes;
    for (const auto &name : selection.functions) {
        const auto marker = selection.markers.find(name);
        recipes.emplace(name, resolve_recipe(configuration, name,
            marker == selection.markers.end() ? llvm::StringRef{} : llvm::StringRef(marker->second),
            options.strategy, selection.deep.count(name), selection.regions.count(name), options.seed));
    }
    const bool single_bounded_schema4_sites = !original_edge_plan_sha256.empty() && recipes.size() == 1 &&
        recipes.begin()->second.strategy == "relative-tree" && recipes.begin()->second.coverage == "whole" &&
        recipes.begin()->second.contribution_options.selection == ContributionSelection::original_edges &&
        recipes.begin()->second.contribution_options.minimum_edges == 3 &&
        recipes.begin()->second.contribution_options.maximum_edges == 8 &&
        recipes.begin()->second.contribution_options.minimum_percent == 100;
    const bool post_bounded_schema4_sites = !original_edge_plan_sha256.empty() &&
        options.original_edge_owners == post_edge_owners;
    if (post_bounded_schema4_sites) for (const auto *name :
            {"pyobf_demo_bound_compute", "pyobf_demo_protection_wrapper"}) {
        const auto found = recipes.find(name);
        if (found == recipes.end() || found->second.strategy != "relative-tree" ||
                found->second.coverage != "whole" ||
                found->second.contribution_options.selection != ContributionSelection::original_edges ||
                found->second.contribution_options.minimum_edges != 3 ||
                found->second.contribution_options.maximum_edges != 8 ||
                found->second.contribution_options.minimum_percent != 100 ||
                !found->second.enabled("runtime-contribution"))
            llvm::report_fatal_error("POST original-edge owners need two complete bounded recipes");
    }
    const bool bounded_schema4_sites = single_bounded_schema4_sites || post_bounded_schema4_sites;
    const auto contribution = read_contribution_private(options.contribution_input, bounded_schema4_sites);
    if (post_bounded_schema4_sites && (contribution == nullptr || contribution->schema != 4 ||
            !contribution->provider_split || contribution->owners.size() != 2 ||
            !contribution->owners.count("pyobf_demo_bound_compute") ||
            !contribution->owners.count("pyobf_demo_protection_wrapper")))
        llvm::report_fatal_error("POST original-edge plan needs exact two-owner provider-split private input");
    for (auto &[name, recipe] : recipes) {
        recipe.contribution = contribution;
        if (auto *function = module.getFunction(name)) configure_region(recipe, *function, selection);
    }
    if (options.original_edge_plan_input.empty())
        for (const auto &entry : recipes) {
            const auto &recipe = entry.second;
            if (recipe.contribution && recipe.contribution->schema == 4 &&
                    recipe.contribution_options.selection == ContributionSelection::original_edges)
                llvm::report_fatal_error("schema4 original edges require frozen exact-IR plan");
        }
    llvm::json::Array functions;
    archive::preflight_prepared(module, recipes);
    FrameProfileSeal frame_profiles(module);
    OwnerReaderSeal owner_readers(module, selection.functions);
    OwnerCreatorSeal owner_creators(module, selection.functions);
    PostRoleFlowSeal post_roles(module, selection.functions);
    PostChildSeal post_child(module, selection.functions, post_bounded_schema4_sites);
    const auto generated = prepare_module_components(module, recipes, options.seed);
    if (const auto reason = frame_profiles.bind(module, generated); !reason.empty())
        llvm::report_fatal_error(llvm::StringRef(reason));
    for (const auto &[name, definition] : generated) selection.functions.insert(name);
    llvm::json::Array maps;
    bool failed = false;
    std::set<std::string> seen;
    for (auto &function : module) {
        const auto name = function.getName().str();
        seen.insert(name);
        const bool selected = selection.functions.count(name);
        llvm::json::Object item;
        item["function"] = name;
        item["selected"] = selected;
        item["requested"] = selected && !generated.count(name);
        item["retained"] = !function.isDeclaration();
        if (const auto found = generated.find(name); found != generated.end()) {
            item["generated"] = true;
            item["generated_owner"] = found->second.owner;
            item["generated_site"] = found->second.site;
            item["generation_component"] = found->second.component;
        }
        if (!selected) {
            item["status"] = function.isDeclaration() ? "declaration" : "unselected";
            functions.push_back(std::move(item));
            continue;
        }
        const auto &recipe = recipes.at(name);
        const bool hybrid = recipe.coverage == "hybrid-eh";
        if (hybrid && !function.isDeclaration()) item["hybrid_eh"] = describe_hybrid_eh(function);
        item["strategy"] = recipe.strategy;
        item["effective_recipe"] = describe_recipe(recipe);
        const auto region = selection.regions.find(name);
        const auto request = selection.requests.find(name);
        if (const auto marker = selection.markers.find(name); marker != selection.markers.end())
            item["marker"] = marker->second;
        if (region != selection.regions.end()) {
            item["region_entry"] = region->second.entry;
            item["region_exit"] = region->second.exit;
        }
        if (function.isDeclaration()) {
            const bool removed = request != selection.requests.end() && request->second.defined;
            item["status"] = removed ? "optimized-away" : "unsupported";
            item["reason"] = removed ? "requested definition became a declaration before native CFF" :
                                       "selected function is a declaration";
            item["components"] = absent_site_coverage(recipe,
                request == selection.requests.end() ? std::vector<RequestedSite>{} : request->second.sites,
                removed ? "optimized-away" : "unsupported", "selected definition is unavailable");
            failed = true;
        } else {
            stamp_site_provenance(function, "input");
            const std::vector<RequestedSite> empty;
            const auto &requested = request == selection.requests.end() ? empty : request->second.sites;
            bool track_archive_sources = function.hasFnAttribute("pyobf.archive.planned");
            if (recipe.enabled("constant-archive")) for (const auto &site : requested)
                track_archive_sources |= site.component == "constant-archive";
            std::vector<RequestedSite> physical_requests;
            for (const auto &site : requested) if (site.component != "constant-archive") physical_requests.push_back(site);
            SiteCoverage coverage(function, recipe, physical_requests,
                region == selection.regions.end() ? llvm::StringRef{} : region->second.entry,
                region == selection.regions.end() ? llvm::StringRef{} : region->second.exit);
            std::string reason = region != selection.regions.end() ?
                validate_relative_tree_region(function, region->second.entry, region->second.exit) :
                validate_configured(function, recipe);
            if (reason.empty()) {
                if (region == selection.regions.end()) reason = validate_body_budget(function, recipe);
                else if (coverage.original_blocks + 1 > recipe.max_body_blocks ||
                         coverage.original_blocks + 1 < recipe.min_blocks)
                    reason = "selected region body count is outside the configured block budget";
            }
            if (reason.empty() && recipe.legacy_deep &&
                !(recipe.enabled("integer-literals") && has_eligible_integer_constants(function)) &&
                !(recipe.enabled("internal-calls") && has_eligible_internal_calls(function)))
                reason = "relative-tree-deep needs an eligible scalar integer literal or internal call";
            const bool decision = region != selection.regions.end() ? coverage.real_decisions != 0 :
                                  has_control_decision(function);
            item["coverage_kind"] = region != selection.regions.end() ?
                decision ? "region-decision-flow" : "region-straight-line" :
                                      decision ? "decision-flow" : "shape-only";
            item["input_coverage_kind"] = region != selection.regions.end() ?
                decision ? "region-decision-flow" : "region-straight-line" :
                decision ? "decision-flow" : "shape-only";
            if (hybrid) {
                item["coverage_kind"] = decision ? "hybrid-eh-decision-flow" : "hybrid-eh-straight-line";
                item["input_coverage_kind"] = decision ? "hybrid-eh-decision-flow" : "hybrid-eh-straight-line";
            }
            if (reason.empty() && options.require_decision_flow && !decision)
                reason = "selected function has no original decision flow";
            if (reason.empty()) reason = coverage.required_failure();
            if (reason.empty() && track_archive_sources)
                reason = archive::inspect_sources(function, requested, false,
                    recipe.strict_components.count("constant-archive")).failure;
            if (reason.empty()) {
                if (region != selection.regions.end()) {
                    reason = flatten_region_configured(function, recipe, coverage);
                } else reason = flatten_configured(function, recipe, coverage);
                if (!hybrid && region == selection.regions.end() && decision && coverage.normalized_decisions == 0)
                    item["coverage_kind"] = "normalized-straight-line";
                if (reason.empty() && options.require_decision_flow && coverage.normalized_decisions == 0)
                    reason = "normalization removed all protected decision flow";
                if (reason.empty()) reason = coverage.required_failure(true);
            }
            llvm::json::Array archive_source_map;
            if (track_archive_sources) {
                auto sources = archive::inspect_sources(function, requested, reason.empty(),
                    recipe.strict_components.count("constant-archive"));
                if (reason.empty()) reason = sources.failure;
                item["archive_sources"] = std::move(sources.report);
                if (!options.private_map.empty()) {
                    archive_source_map = std::move(sources.private_map);
                }
            }
            if (!reason.empty()) {
                coverage.failed(reason);
                item["status"] = "unsupported";
                item["reason"] = reason;
                failed = true;
            } else {
                item["status"] = "transformed";
                item["transition_layer_contract_verified"] = function.hasFnAttribute("pyobf.transition.layers.verified");
                item["bogus_control_contract_verified"] = function.hasFnAttribute("pyobf.bogus.controls.verified");
                if (region != selection.regions.end()) item["region_flow_contract_verified"] = function.hasFnAttribute("pyobf.region.verified");
                if (hybrid) {
                    (*item.getObject("hybrid_eh"))["ir_boundary_contract_verified"] = true;
                    (*item.getObject("hybrid_eh"))["ir_flow_graph_verified"] = true;
                }
            }
            if (recipe.enabled("path-fold")) item["path_fold"] = llvm::json::Object{
                {"scheme_version", 1}, {"storage_bits", 256},
                {"ir_binding_contract_verified", reason.empty() && function.hasFnAttribute("pyobf.path-fold.bound")}};
            if (recipe.enabled("runtime-contribution")) item["runtime_contribution"] = llvm::json::Object{
                {"scheme_version", 1}, {"provider", recipe.contribution ? recipe.contribution->provider : "owned-context-v1"},
                {"private_input_sha256", recipe.contribution ? recipe.contribution->input_sha256 : ""},
                {"acquisition", recipe.contribution_options.selection == ContributionSelection::original_edges ? "original-edges-and-explicit-points" : "explicit-source-point"},
                {"source_bits", 32}, {"ir_binding_contract_verified", reason.empty() && function.hasFnAttribute("pyobf.contribution.bound")},
                {"original_real_edge_density_verified", false}};
            if (recipe.enabled("runtime-contribution") && recipe.contribution && recipe.contribution->provider == "measured-scope-v1") {
                auto &proof = *item.getObject("runtime_contribution");
                proof["operation_scope"] = "function-invocation";
                proof["evidence_bits"] = 256;
                proof["generated_owner_independence_verified"] = false;
            }
            if (recipe.enabled("runtime-contribution") && recipe.contribution && recipe.contribution->schema >= 2)
                report_contribution_groups(*item.getObject("runtime_contribution"), function, recipe);
            if (coverage.contribution_edges) {
                auto edges = coverage.contribution_edges->report(reason.empty());
                (*item.getObject("runtime_contribution"))["original_real_edge_density_verified"] = edges.getBoolean("density_verified").value_or(false);
                (*item.getObject("runtime_contribution"))["original_edges"] = std::move(edges);
            }
            item["components"] = coverage.components();
            item["site_totals"] = coverage.totals();
            if (!options.private_map.empty()) {
                coverage.capture_transformed_map(function);
                llvm::json::Object map;
                map["function"] = name;
                map["sites"] = coverage.private_map();
                if (!archive_source_map.empty()) map["archive_sources"] = std::move(archive_source_map);
                maps.push_back(std::move(map));
            }
        }
        functions.push_back(std::move(item));
    }
    for (const auto &name : selection.functions) {
        if (seen.count(name)) continue;
        const auto request = selection.requests.find(name);
        const bool removed = request != selection.requests.end() && request->second.defined;
        llvm::json::Object item;
        item["function"] = name;
        item["selected"] = true;
        item["requested"] = true;
        item["retained"] = false;
        item["strategy"] = recipes.at(name).strategy;
        item["effective_recipe"] = describe_recipe(recipes.at(name));
        item["status"] = removed ? "optimized-away" : "missing";
        item["reason"] = removed ? "requested definition is absent before native CFF" :
                                   "function is absent from the input module";
        item["components"] = absent_site_coverage(recipes.at(name),
            request == selection.requests.end() ? std::vector<RequestedSite>{} : request->second.sites,
            removed ? "optimized-away" : "unsupported", "selected definition is unavailable");
        if (const auto marker = selection.markers.find(name); marker != selection.markers.end())
            item["marker"] = marker->second;
        if (const auto region = selection.regions.find(name); region != selection.regions.end()) {
            item["region_entry"] = region->second.entry;
            item["region_exit"] = region->second.exit;
        }
        functions.push_back(std::move(item));
        failed = true;
    }
    llvm::json::Object report;
    report["schema_version"] = 2;
    report["module"] = module.getModuleIdentifier();
    report["domain"] = configuration.domain;
    report["strategy"] = options.strategy;
    report["llvm_version"] = LLVM_VERSION_STRING;
    report["target_triple"] = module.getTargetTriple().str();
    report["data_layout"] = module.getDataLayoutStr();
    if (!original_edge_plan_sha256.empty())
        report["original_edge_plan_sha256"] = original_edge_plan_sha256;
    auto dependency_contract = configuration.dependency_contract.empty() ?
        validate_dependency_contract({}, configuration.domain) : configuration.dependency_contract;
    report["dependency_contract"] = std::move(dependency_contract);
    if (!failed) {
        if (const auto reason = frame_profiles.verify(module); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(reason));
        archive::finish_bindings(module);
        if (const auto reason = verify_indexed_locals(module); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(reason));
        if (const auto reason = verify_call_preparation(module); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(reason));
        finish_call_frames(module);
        strip_call_preparation(module);
        finish_reference_routes(module);
        strip_indexed_locals(module);
        report["generated_ownership"] = generated_ownership(module, generated, functions);
        if (!owner_readers.empty()) report["owner_readers"] = owner_readers.verify(module);
        if (!owner_creators.empty()) report["owner_creators"] = owner_creators.verify(module);
        if (!post_roles.empty()) report["post_role_flow"] = post_roles.verify(module);
        if (!post_child.empty()) report["post_child_flow"] = post_child.verify(module);
    }
    report["functions"] = std::move(functions);
    write_json_report(options.report, std::move(report));
    if (!options.private_map.empty()) {
        llvm::json::Object map;
        map["schema_version"] = 1;
        map["domain"] = configuration.domain;
        map["functions"] = std::move(maps);
        write_json_report(options.private_map, std::move(map));
    }
    if (failed)
        llvm::report_fatal_error("native CFF selection was not fully transformed; see coverage report");
}

}  // namespace pyobfuscator::native::cff
