#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/JSON.h"
#include "llvm/IR/IRBuilder.h"
#include "contribution_options.hpp"

namespace llvm {
class Function;
class Instruction;
class Module;
}

namespace pyobfuscator::native::cff {

enum class Requirement { off, optional, required };
enum class MutationStage { route = 2, structure = 4, bind = 5 };

class SiteCoverage;
struct ResolvedRecipe;
struct ContributionPrivate;
struct TransitionModelRegistration;
class RegionScope;

struct InstructionSite {
    llvm::Instruction *instruction;
    unsigned operand;
    std::string reason;
};

struct GeneratedDefinition;

struct Component {
    const char *name;
    MutationStage stage;
    const char *scope;
    const char *analyses;
    const char *runtime_dependency;
    bool changes_cfg;
    std::vector<InstructionSite> (*discover)(llvm::Function &, const ResolvedRecipe &);
    unsigned (*route)(llvm::Function &, llvm::ArrayRef<llvm::BasicBlock *>, SiteCoverage *, unsigned);
    unsigned (*bind)(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t, SiteCoverage *);
    llvm::Value *(*transition)(llvm::IRBuilder<> &, llvm::Value *, llvm::Value *,
                               std::uint32_t, std::uint32_t, const ResolvedRecipe &);
    unsigned (*normalize)(llvm::Function &, const ResolvedRecipe &, SiteCoverage &) = nullptr;
    unsigned (*prepare)(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &) = nullptr;
    bool (*transition_selected)(const llvm::Instruction &) = nullptr;
    unsigned (*identity_operand)(const llvm::Instruction &, unsigned) = nullptr;
    void (*module_prepare)(llvm::Module &, const std::map<std::string, ResolvedRecipe> &,
                            std::vector<GeneratedDefinition> &) = nullptr;
    void (*retain_source)(llvm::Function &, const ResolvedRecipe &) = nullptr;
    const TransitionModelRegistration *transition_model = nullptr;
};

std::vector<InstructionSite> discover_cfg_sites(llvm::Function &, const ResolvedRecipe &);
std::vector<InstructionSite> discover_integer_sites(llvm::Function &, const ResolvedRecipe &);
std::vector<InstructionSite> discover_comparison_sites(llvm::Function &, const ResolvedRecipe &);
unsigned hide_comparison_constants(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t,
                                     SiteCoverage *);
unsigned comparison_identity_operand(const llvm::Instruction &, unsigned);
std::vector<InstructionSite> discover_archive_sites(llvm::Function &, const ResolvedRecipe &);
unsigned bind_archive_keys(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t, SiteCoverage *);
std::vector<InstructionSite> discover_internal_call_sites(llvm::Function &, const ResolvedRecipe &);
std::vector<InstructionSite> discover_decoy_sites(llvm::Function &, const ResolvedRecipe &);
std::vector<InstructionSite> discover_split_sites(llvm::Function &, const ResolvedRecipe &);
unsigned split_blocks(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
std::vector<InstructionSite> discover_dedup_sites(llvm::Function &, const ResolvedRecipe &);
unsigned deduplicate_blocks(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
std::vector<InstructionSite> discover_exit_sites(llvm::Function &, const ResolvedRecipe &);
unsigned normalize_exits(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
std::vector<InstructionSite> discover_opaque_sites(llvm::Function &, const ResolvedRecipe &);
unsigned prepare_opaque_choices(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
bool opaque_transition_selected(const llvm::Instruction &);
llvm::Value *select_opaque_transition(llvm::IRBuilder<> &, llvm::Value *, llvm::Value *,
                                      std::uint32_t, std::uint32_t, const ResolvedRecipe &);
std::vector<InstructionSite> discover_junk_sites(llvm::Function &, const ResolvedRecipe &);
unsigned prepare_reachable_junk(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
bool junk_transition_selected(const llvm::Instruction &);
llvm::Value *apply_reachable_junk(llvm::IRBuilder<> &, llvm::Value *, llvm::Value *,
                                  std::uint32_t, std::uint32_t, const ResolvedRecipe &);
std::vector<InstructionSite> discover_bogus_clone_sites(llvm::Function &, const ResolvedRecipe &);
unsigned prepare_bogus_clones(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
unsigned bind_bogus_clones(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t, SiteCoverage *);
std::vector<InstructionSite> discover_bogus_synthesis_sites(llvm::Function &, const ResolvedRecipe &);
unsigned prepare_bogus_synthesis(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
unsigned bind_bogus_synthesis(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t, SiteCoverage *);
std::string validate_body_budget(llvm::Function &, const ResolvedRecipe &, bool structural_finished = false);

llvm::ArrayRef<Component> registered_components();
const Component *find_component(llvm::StringRef name);
const char *requirement_name(Requirement requirement);
std::uint32_t component_seed(unsigned seed, llvm::StringRef function,
                             llvm::StringRef component);

struct RecipeOverride {
    ContributionOverride contribution_override;
    std::string recipe;
    std::optional<std::string> coverage;
    std::map<std::string, Requirement> components;
    std::optional<unsigned> min_blocks;
    std::optional<unsigned> max_body_blocks;
    std::optional<unsigned> max_block_instructions;
    std::optional<unsigned> max_dedup_comparisons;
    std::optional<unsigned> max_opaque_sites;
    std::optional<unsigned> max_junk_sites;
    std::optional<unsigned> junk_rounds;
    std::optional<unsigned> max_bogus_blocks;
    std::optional<unsigned> max_clone_instructions;
    std::optional<unsigned> clone_percent;
    std::optional<unsigned> synthesis_rounds;
    std::optional<unsigned> max_reference_slots;
    std::optional<unsigned> max_reference_sites;
    std::optional<unsigned> max_import_slots, max_import_sites;
    std::optional<unsigned> max_frame_sites, max_frame_bytes, max_frame_total_bytes;
    std::optional<unsigned> max_preparation_steps;
    std::optional<unsigned> max_local_slots, max_local_routes, max_local_bytes;
    std::optional<unsigned> max_path_fold_sites;
    std::optional<unsigned> max_contribution_sites;
};

struct GeneratedDefinition {
    llvm::Function *function;
    std::string owner, site, component;
    RecipeOverride support;
};

struct RecipeConfiguration {
    std::string domain = "module";
    RecipeOverride defaults;
    std::map<std::string, RecipeOverride> functions;
    std::map<std::string, RecipeOverride> markers;
    llvm::json::Object dependency_contract;
};

struct ResolvedRecipe {
    std::shared_ptr<RegionScope> region_scope;
    ContributionOptions contribution_options;
    std::string name;
    std::string strategy;
    std::string coverage = "whole";
    bool legacy_deep = false;
    unsigned min_blocks = 3;
    unsigned max_body_blocks = 4096;
    unsigned max_block_instructions = 16;
    unsigned max_dedup_comparisons = 65536;
    unsigned max_opaque_sites = 4;
    unsigned max_junk_sites = 4;
    unsigned junk_rounds = 2;
    unsigned max_bogus_blocks = 4;
    unsigned max_clone_instructions = 6;
    unsigned clone_percent = 50;
    unsigned synthesis_rounds = 2;
    unsigned max_reference_slots = 256;
    unsigned max_reference_sites = 4096;
    unsigned max_import_slots = 256, max_import_sites = 4096;
    unsigned max_frame_sites = 256, max_frame_bytes = 4096, max_frame_total_bytes = 65536;
    unsigned max_preparation_steps = 1024;
    unsigned max_local_slots = 256, max_local_routes = 4096, max_local_bytes = 65536;
    unsigned max_path_fold_sites = 256;
    unsigned max_contribution_sites = 256;
    std::shared_ptr<const ContributionPrivate> contribution;
    std::set<std::string> strict_components;
    std::map<std::string, Requirement> components;
    std::map<std::string, std::uint32_t> seeds;

    bool enabled(llvm::StringRef name) const;
    Requirement requirement(llvm::StringRef name) const;
};

RecipeConfiguration read_recipe_configuration(llvm::StringRef path);
ResolvedRecipe resolve_recipe(const RecipeConfiguration &configuration,
                               llvm::StringRef function, llvm::StringRef marker,
                               llvm::StringRef strategy, bool deep, bool region,
                               unsigned seed, bool generated_support = false);
llvm::json::Object describe_recipe(const ResolvedRecipe &recipe);
llvm::json::Object validate_dependency_contract(const llvm::json::Object &root,
                                                llvm::StringRef domain);

}  // namespace pyobfuscator::native::cff
