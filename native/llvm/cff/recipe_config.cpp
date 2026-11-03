#include "recipe.hpp"
#include "hybrid_eh.hpp"

#include <set>

#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MemoryBuffer.h"

namespace pyobfuscator::native::cff {
namespace {

[[noreturn]] void invalid(const std::string &message) {
    llvm::report_fatal_error(llvm::StringRef("native CFF configuration: " + message));
}

void fields(const llvm::json::Object &object, std::initializer_list<llvm::StringRef> allowed) {
    for (const auto &entry : object) {
        bool known = false;
        for (const auto name : allowed) known |= llvm::StringRef(entry.first) == name;
        if (!known) invalid("unknown field '" + entry.first.str() + "'");
    }
}

RecipeOverride read_override(const llvm::json::Object &object) {
    fields(object, {"recipe", "coverage", "components", "budgets", "contribution"});
    RecipeOverride result;
    if (const auto *value = object.get("contribution")) result.contribution_override = read_contribution_options(*value);
    if (const auto *value = object.get("coverage")) {
        const auto scope = value->getAsString();
        if (!scope || (*scope != "whole" && *scope != "hybrid-eh"))
            invalid("coverage must be whole or hybrid-eh");
        result.coverage = scope->str();
    }
    if (const auto *value = object.get("recipe")) {
        const auto name = value->getAsString();
        if (!name || name->empty()) invalid("recipe must be a nonempty string");
        result.recipe = name->str();
        if (result.recipe != "baseline" && result.recipe != "deep" &&
            result.recipe != "relative-tree" && result.recipe != "relative-tree-deep" &&
            result.recipe != "parity") invalid("unknown recipe '" + result.recipe + "'");
    }
    if (const auto *value = object.get("components")) {
        const auto *components = value->getAsObject();
        if (components == nullptr) invalid("components must be an object");
        for (const auto &entry : *components) {
            if (find_component(entry.first) == nullptr)
                invalid("unknown or unimplemented component '" + entry.first.str() + "'");
            const auto mode = entry.second.getAsString();
            if (!mode || (*mode != "off" && *mode != "optional" && *mode != "required"))
                invalid("component mode must be off, optional or required");
            result.components.emplace(entry.first.str(), *mode == "off" ? Requirement::off :
                *mode == "optional" ? Requirement::optional : Requirement::required);
        }
    }
    if (const auto *value = object.get("budgets")) {
        const auto *budgets = value->getAsObject();
        if (budgets == nullptr) invalid("budgets must be an object");
        fields(*budgets, {"min_blocks", "max_body_blocks", "max_block_instructions", "max_dedup_comparisons",
                          "max_opaque_sites", "max_junk_sites", "junk_rounds", "max_bogus_blocks",
                          "max_clone_instructions", "clone_percent", "synthesis_rounds",
                          "max_reference_slots", "max_reference_sites", "max_import_slots", "max_import_sites", "max_frame_sites", "max_frame_bytes",
                          "max_frame_total_bytes", "max_preparation_steps", "max_local_slots", "max_local_routes", "max_local_bytes", "max_path_fold_sites", "max_contribution_sites"});
        const auto read_budget = [&](llvm::StringRef name, std::optional<unsigned> &output) {
            if (budgets->get(name) == nullptr) return;
            const auto amount = budgets->getInteger(name);
            if (!amount || *amount < 1 || *amount > 1048576)
                invalid("budget '" + name.str() + "' must be an integer from 1 to 1048576");
            output = static_cast<unsigned>(*amount);
        };
        read_budget("min_blocks", result.min_blocks);
        read_budget("max_body_blocks", result.max_body_blocks);
        read_budget("max_block_instructions", result.max_block_instructions);
        read_budget("max_dedup_comparisons", result.max_dedup_comparisons);
        read_budget("max_opaque_sites", result.max_opaque_sites);
        read_budget("max_junk_sites", result.max_junk_sites);
        read_budget("junk_rounds", result.junk_rounds);
        if (result.junk_rounds && *result.junk_rounds > 8) invalid("junk_rounds must be between 1 and 8");
        read_budget("max_bogus_blocks", result.max_bogus_blocks);
        read_budget("max_clone_instructions", result.max_clone_instructions);
        read_budget("synthesis_rounds", result.synthesis_rounds);
        read_budget("max_reference_slots", result.max_reference_slots);
        read_budget("max_reference_sites", result.max_reference_sites);
        read_budget("max_import_slots", result.max_import_slots);
        read_budget("max_import_sites", result.max_import_sites);
        if (result.max_import_slots && (*result.max_import_slots < 2 || *result.max_import_slots > 4096 ||
                (*result.max_import_slots & (*result.max_import_slots - 1))))
            invalid("max_import_slots must be a power of two from 2 through 4096");
        read_budget("max_frame_sites", result.max_frame_sites);
        read_budget("max_frame_bytes", result.max_frame_bytes);
        read_budget("max_frame_total_bytes", result.max_frame_total_bytes);
        read_budget("max_preparation_steps", result.max_preparation_steps);
        read_budget("max_local_slots", result.max_local_slots);
        read_budget("max_local_routes", result.max_local_routes);
        read_budget("max_local_bytes", result.max_local_bytes);
        read_budget("max_path_fold_sites", result.max_path_fold_sites);
        read_budget("max_contribution_sites", result.max_contribution_sites);
        if (result.max_local_slots && (*result.max_local_slots < 2 || *result.max_local_slots > 4096 ||
                (*result.max_local_slots & (*result.max_local_slots - 1))))
            invalid("max_local_slots must be a power of two from 2 through 4096");
        if (result.max_reference_slots && (*result.max_reference_slots < 2 || *result.max_reference_slots > 4096 ||
                (*result.max_reference_slots & (*result.max_reference_slots - 1))))
            invalid("max_reference_slots must be a power of two from 2 through 4096");
        if (result.max_clone_instructions && *result.max_clone_instructions > 64)
            invalid("max_clone_instructions must be between 1 and 64");
        if (result.synthesis_rounds && *result.synthesis_rounds > 8)
            invalid("synthesis_rounds must be between 1 and 8");
        if (budgets->get("clone_percent") != nullptr) {
            const auto percent = budgets->getInteger("clone_percent");
            if (!percent || *percent < 0 || *percent > 100) invalid("clone_percent must be between 0 and 100");
            result.clone_percent = static_cast<unsigned>(*percent);
        }
    }
    return result;
}

void read_overrides(const llvm::json::Object &root, llvm::StringRef field,
                    std::map<std::string, RecipeOverride> &output) {
    const auto *value = root.get(field);
    if (value == nullptr) return;
    const auto *object = value->getAsObject();
    if (object == nullptr) invalid(field.str() + " must be an object");
    for (const auto &entry : *object) {
        const auto *override = entry.second.getAsObject();
        if (llvm::StringRef(entry.first).empty() || override == nullptr) invalid("invalid override");
        output.emplace(entry.first.str(), read_override(*override));
    }
}

void set_recipe(ResolvedRecipe &result, llvm::StringRef recipe) {
    if (recipe == "parity") invalid("parity requires components not yet implemented");
    result.name = recipe == "deep" || recipe == "relative-tree-deep" ? "deep" : "baseline";
    result.strategy = result.name == "deep" ? "relative-tree-deep" : "relative-tree";
    result.legacy_deep = result.name == "deep";
    result.strict_components.clear();
    for (const auto &component : registered_components()) {
        const auto name = llvm::StringRef(component.name);
        result.components[component.name] = result.name == "deep" &&
            (name == "integer-literals" || name == "internal-calls" || name == "decoy-transitions") ?
            Requirement::optional : Requirement::off;
    }
    result.components["cfg"] = Requirement::required;
}

void apply_override(ResolvedRecipe &result, const RecipeOverride &override) {
    apply_contribution_options(result.contribution_options, override.contribution_override);
    if (!override.recipe.empty()) set_recipe(result, override.recipe);
    if (override.coverage) result.coverage = *override.coverage;
    for (const auto &[name, mode] : override.components) {
        result.components[name] = mode;
        if (mode == Requirement::required) result.strict_components.insert(name);
        else result.strict_components.erase(name);
    }
    if (override.min_blocks) result.min_blocks = *override.min_blocks;
    if (override.max_body_blocks) result.max_body_blocks = *override.max_body_blocks;
    if (override.max_block_instructions) result.max_block_instructions = *override.max_block_instructions;
    if (override.max_dedup_comparisons) result.max_dedup_comparisons = *override.max_dedup_comparisons;
    if (override.max_opaque_sites) result.max_opaque_sites = *override.max_opaque_sites;
    if (override.max_junk_sites) result.max_junk_sites = *override.max_junk_sites;
    if (override.junk_rounds) result.junk_rounds = *override.junk_rounds;
    if (override.max_bogus_blocks) result.max_bogus_blocks = *override.max_bogus_blocks;
    if (override.max_clone_instructions) result.max_clone_instructions = *override.max_clone_instructions;
    if (override.clone_percent) result.clone_percent = *override.clone_percent;
    if (override.synthesis_rounds) result.synthesis_rounds = *override.synthesis_rounds;
    if (override.max_reference_slots) result.max_reference_slots = *override.max_reference_slots;
    if (override.max_reference_sites) result.max_reference_sites = *override.max_reference_sites;
    if (override.max_import_slots) result.max_import_slots = *override.max_import_slots;
    if (override.max_import_sites) result.max_import_sites = *override.max_import_sites;
    if (override.max_frame_sites) result.max_frame_sites = *override.max_frame_sites;
    if (override.max_frame_bytes) result.max_frame_bytes = *override.max_frame_bytes;
    if (override.max_frame_total_bytes) result.max_frame_total_bytes = *override.max_frame_total_bytes;
    if (override.max_preparation_steps) result.max_preparation_steps = *override.max_preparation_steps;
    if (override.max_local_slots) result.max_local_slots = *override.max_local_slots;
    if (override.max_local_routes) result.max_local_routes = *override.max_local_routes;
    if (override.max_local_bytes) result.max_local_bytes = *override.max_local_bytes;
    if (override.max_path_fold_sites) result.max_path_fold_sites = *override.max_path_fold_sites;
    if (override.max_contribution_sites) result.max_contribution_sites = *override.max_contribution_sites;
}

}  // namespace

RecipeConfiguration read_recipe_configuration(llvm::StringRef path) {
    RecipeConfiguration result;
    if (path.empty()) {
        result.dependency_contract = validate_dependency_contract({}, result.domain);
        return result;
    }
    const auto input = llvm::MemoryBuffer::getFile(path);
    if (!input) invalid("cannot read file");
    auto parsed = llvm::json::parse(input.get()->getBuffer());
    if (!parsed) {
        llvm::consumeError(parsed.takeError());
        invalid("invalid JSON");
    }
    const auto *root = parsed->getAsObject();
    if (root == nullptr) invalid("root must be an object");
    fields(*root, {"schema_version", "domain", "defaults", "functions", "markers",
                   "build_domains", "runtime_services"});
    if (root->getInteger("schema_version") != 1) invalid("schema_version must be 1");
    if (const auto *value = root->get("domain")) {
        const auto domain = value->getAsString();
        if (!domain || domain->empty()) invalid("domain must be a nonempty string");
        result.domain = domain->str();
    }
    if (const auto *value = root->get("defaults")) {
        const auto *defaults = value->getAsObject();
        if (defaults == nullptr) invalid("defaults must be an object");
        result.defaults = read_override(*defaults);
    }
    read_overrides(*root, "functions", result.functions);
    read_overrides(*root, "markers", result.markers);
    result.dependency_contract = validate_dependency_contract(*root, result.domain);
    return result;
}

ResolvedRecipe resolve_recipe(const RecipeConfiguration &configuration,
                               llvm::StringRef function, llvm::StringRef marker,
                               llvm::StringRef strategy, bool deep, bool region,
                               unsigned seed, bool generated_support) {
    ResolvedRecipe result;
    set_recipe(result, deep ? "deep" : strategy);
    apply_override(result, configuration.defaults);
    if (const auto found = configuration.markers.find(marker.str());
        found != configuration.markers.end()) apply_override(result, found->second);
    if (const auto found = configuration.functions.find(function.str());
        found != configuration.functions.end()) apply_override(result, found->second);
    if (!result.enabled("cfg")) invalid("cfg cannot be disabled for a selected scope");
    if (result.enabled("runtime-contribution") && result.contribution_options.selection == ContributionSelection::original_edges)
        for (const auto &component : registered_components())
            if (result.enabled(component.name) && component.prepare != nullptr && component.changes_cfg &&
                    component.transition_model == nullptr && llvm::StringRef(component.name) != "runtime-contribution" &&
                    llvm::StringRef(component.name) != "call-preparation" &&
                    llvm::StringRef(component.name) != "bogus-clones" && llvm::StringRef(component.name) != "bogus-synthesis")
                invalid("automatic contribution preparation composition is not implemented yet");
    if (result.enabled("runtime-contribution"))
        for (const auto &component : registered_components())
            if (result.enabled(component.name) && component.transition != nullptr &&
                    component.transition_model == nullptr && llvm::StringRef(component.name) != "runtime-contribution")
                invalid("runtime-contribution transition composition is not implemented yet");
    if (result.coverage == "hybrid-eh") {
        if (region) invalid("hybrid-eh coverage conflicts with explicit regions");
        for (const auto &component : registered_components())
            if (result.enabled(component.name) && !hybrid_component_supported(component.name))
                invalid("hybrid-eh does not support component '" + std::string(component.name) + "' yet");
    }
    if (result.enabled("reference-routes") && result.enabled("internal-calls"))
        invalid("reference-routes and legacy internal-calls are mutually exclusive in one scope");
    if (result.enabled("call-frames") && result.enabled("internal-calls"))
        invalid("call-frames and legacy internal-calls are mutually exclusive in one scope");
    if (result.enabled("external-calls") && result.enabled("internal-calls"))
        invalid("external-calls and legacy internal-calls are mutually exclusive in one scope");
    if (!generated_support && result.enabled("call-preparation") &&
        !result.enabled("call-frames") && !result.enabled("external-calls"))
        invalid("call-preparation requires source call-frames or external-calls");
    if (result.min_blocks < 3 || result.min_blocks > result.max_body_blocks)
        invalid("min_blocks must be at least 3 and not exceed max_body_blocks");
    if (result.legacy_deep && !result.enabled("integer-literals") &&
        !result.enabled("internal-calls"))
        invalid("deep requires an enabled literal or internal-call component");
    for (const auto &component : registered_components()) {
        if (region && result.enabled(component.name) &&
            llvm::StringRef(component.scope) == "function")
            invalid("component '" + std::string(component.name) + "' does not support regions");
        result.seeds[component.name] = component_seed(seed, function, component.name);
    }
    if (region) result.strategy = "relative-tree-region";
    return result;
}

llvm::json::Object describe_recipe(const ResolvedRecipe &recipe) {
    llvm::json::Object output;
    output["name"] = recipe.name;
    output["strategy"] = recipe.strategy;
    output["coverage"] = recipe.coverage;
    output["contribution"] = describe_contribution_options(recipe.contribution_options);
    output["budgets"] = llvm::json::Object{
        {"min_blocks", recipe.min_blocks}, {"max_body_blocks", recipe.max_body_blocks},
        {"max_block_instructions", recipe.max_block_instructions},
        {"max_dedup_comparisons", recipe.max_dedup_comparisons},
        {"max_opaque_sites", recipe.max_opaque_sites}, {"max_junk_sites", recipe.max_junk_sites},
        {"junk_rounds", recipe.junk_rounds}, {"max_bogus_blocks", recipe.max_bogus_blocks},
        {"max_clone_instructions", recipe.max_clone_instructions}, {"clone_percent", recipe.clone_percent},
        {"synthesis_rounds", recipe.synthesis_rounds}, {"max_reference_slots", recipe.max_reference_slots},
        {"max_reference_sites", recipe.max_reference_sites}, {"max_frame_sites", recipe.max_frame_sites},
        {"max_import_slots", recipe.max_import_slots}, {"max_import_sites", recipe.max_import_sites},
        {"max_frame_bytes", recipe.max_frame_bytes}, {"max_frame_total_bytes", recipe.max_frame_total_bytes},
        {"max_preparation_steps", recipe.max_preparation_steps}, {"max_local_slots", recipe.max_local_slots},
        {"max_local_routes", recipe.max_local_routes}, {"max_local_bytes", recipe.max_local_bytes},
        {"max_path_fold_sites", recipe.max_path_fold_sites}, {"max_contribution_sites", recipe.max_contribution_sites}};
    llvm::json::Array components;
    for (const auto &component : registered_components()) {
        llvm::json::Object row;
        row["component"] = component.name;
        row["requirement"] = requirement_name(recipe.requirement(component.name));
        row["seed"] = static_cast<std::int64_t>(recipe.seeds.at(component.name));
        row["stage"] = static_cast<int>(component.stage);
        row["scope"] = component.scope;
        row["supports_hybrid_eh"] = hybrid_component_supported(component.name);
        row["supports_transition_composition"] = component.transition_model != nullptr;
        row["analyses"] = component.analyses;
        row["runtime_dependency"] = component.runtime_dependency;
        row["changes_cfg"] = component.changes_cfg;
        row["site_identity"] = component.identity_operand == nullptr ? "operand-index" : "component-semantic-role";
        llvm::json::Object hooks;
        if (component.module_prepare != nullptr) hooks["module_prepare"] = 2;
        if (component.normalize != nullptr) hooks["normalize"] = 4;
        if (component.prepare != nullptr) hooks["prepare"] = 4;
        if (component.route != nullptr) hooks["route"] = 2;
        if (component.bind != nullptr) hooks["bind"] = 5;
        if (component.transition != nullptr) hooks["transition"] = 5;
        row["hook_stages"] = std::move(hooks);
        components.push_back(std::move(row));
    }
    output["components"] = std::move(components);
    return output;
}

}  // namespace pyobfuscator::native::cff
