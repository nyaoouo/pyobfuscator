#include "recipe.hpp"
#include "cff.hpp"
#include "reference_routes.hpp"
#include "call_frames.hpp"
#include "call_preparation.hpp"
#include "indexed_locals.hpp"
#include "external_calls.hpp"
#include "import_routes.hpp"
#include "path_fold_sites.hpp"
#include "contribution_gate.hpp"
#include "transition_registry.hpp"

namespace pyobfuscator::native::cff {

llvm::ArrayRef<Component> registered_components() {
    static const Component components[]{
        {"runtime-contribution", MutationStage::structure, "function-or-region", "explicit-source-point,owned-lease,private-reference,final-state-layout",
         "owned-context", true, discover_contribution_sites, nullptr, nullptr, bind_contribution_transition,
         normalize_contribution_sites, prepare_contribution_sites, contribution_transition_selected},
        {"indexed-locals", MutationStage::structure, "function", "fixed-entry-object,private-table,final-state-layout",
         "none", false, discover_indexed_locals, nullptr, bind_indexed_locals, nullptr,
         normalize_indexed_locals, prepare_indexed_locals},
        {"call-frames", MutationStage::structure, "function", "typed-owned-frame,generated-invoker,lowered-abi",
         "none", true, discover_call_frames, nullptr, nullptr, nullptr, normalize_call_frames,
         nullptr, nullptr, nullptr, plan_call_frames, retain_call_frame_abis},
        {"external-calls", MutationStage::structure, "function", "typed-owned-frame,strong-declaration,lowered-abi",
         "os-loader-imports", true, discover_external_calls, nullptr, nullptr, nullptr, normalize_external_calls,
         nullptr, nullptr, nullptr, plan_external_calls},
        {"call-preparation", MutationStage::structure, "function", "owned-frame,prepared-steps,final-state-layout",
         "none", true, discover_call_preparation, nullptr, bind_call_addresses, nullptr,
         normalize_call_preparation, prepare_call_steps},
        {"common-exit", MutationStage::structure, "function", "return-abi,musttail",
         "none", true, discover_exit_sites, nullptr, nullptr, nullptr, normalize_exits},
        {"deduplicate-blocks", MutationStage::structure, "function", "structural-equivalence,successor-phi",
         "none", true, discover_dedup_sites, nullptr, nullptr, nullptr, deduplicate_blocks},
        {"split-blocks", MutationStage::structure, "function", "legal-instruction-boundaries",
         "none", true, discover_split_sites, nullptr, nullptr, nullptr, split_blocks},
        {"opaque-choices", MutationStage::structure, "function", "prepared-transitions,final-state-layout",
         "none", false, discover_opaque_sites, nullptr, nullptr, select_opaque_transition,
         nullptr, prepare_opaque_choices, opaque_transition_selected, nullptr, nullptr, nullptr, find_transition_model("opaque-choices")},
        {"reachable-junk", MutationStage::structure, "function", "prepared-transitions,final-state-layout",
         "none", false, discover_junk_sites, nullptr, nullptr, apply_reachable_junk,
         nullptr, prepare_reachable_junk, junk_transition_selected, nullptr, nullptr, nullptr, find_transition_model("reachable-junk")},
        {"bogus-clones", MutationStage::structure, "function", "safe-wrapping-donor,prepared-transitions",
         "none", true, discover_bogus_clone_sites, nullptr, bind_bogus_clones, nullptr,
         nullptr, prepare_bogus_clones},
        {"bogus-synthesis", MutationStage::structure, "function", "prepared-transitions,initialized-state",
         "none", true, discover_bogus_synthesis_sites, nullptr, bind_bogus_synthesis, nullptr,
         nullptr, prepare_bogus_synthesis},
        {"reference-routes", MutationStage::structure, "function", "defined-function-reference,private-table,final-state-layout",
         "none", false, discover_reference_sites, nullptr, bind_reference_routes, nullptr,
         normalize_reference_routes, prepare_reference_routes},
        {"import-routes", MutationStage::structure, "function", "strong-declaration,private-table,final-state-layout",
         "os-loader-imports", false, discover_import_sites, nullptr, bind_import_routes, nullptr,
         normalize_import_routes, prepare_import_routes},
        {"internal-calls", MutationStage::route, "function", "lowered-call-abi",
         "none", false, discover_internal_call_sites, route_internal_calls, nullptr, nullptr},
        {"comparison-constants", MutationStage::bind, "function", "scalar-equality,final-state-layout",
         "none", false, discover_comparison_sites, nullptr, hide_comparison_constants, nullptr,
         nullptr, nullptr, nullptr, comparison_identity_operand},
        {"constant-archive", MutationStage::bind, "function", "materialized-pool,source-closure,final-state-layout",
         "archive-runtime", false, discover_archive_sites, nullptr, bind_archive_keys, nullptr},
        {"integer-literals", MutationStage::bind, "function", "final-state-layout",
         "none", false, discover_integer_sites, nullptr, hide_integer_constants, nullptr},
        {"path-fold", MutationStage::bind, "function", "closed-v1-marker,owned-storage,final-state-layout",
         "caller-owned-fold-storage", false, discover_path_fold_sites, nullptr, bind_path_fold_sites, nullptr,
         nullptr, nullptr, nullptr, nullptr, nullptr, retain_path_fold_markers},
        {"decoy-transitions", MutationStage::bind, "function", "final-state-layout",
         "none", false, discover_decoy_sites, nullptr, nullptr, select_decoy_transition,
         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, find_transition_model("decoy-transitions")},
        {"cfg", MutationStage::bind, "function-or-region", "reachable-cfg,ssa",
         "none", true, discover_cfg_sites, nullptr, nullptr, nullptr},
    };
    return components;
}

const Component *find_component(llvm::StringRef name) {
    for (const auto &component : registered_components()) {
        if (name == component.name) return &component;
    }
    return nullptr;
}

const char *requirement_name(Requirement requirement) {
    switch (requirement) {
    case Requirement::off: return "off";
    case Requirement::optional: return "optional";
    case Requirement::required: return "required";
    }
    return "invalid";
}


bool ResolvedRecipe::enabled(llvm::StringRef name) const {
    return requirement(name) != Requirement::off;
}

Requirement ResolvedRecipe::requirement(llvm::StringRef name) const {
    const auto found = components.find(name.str());
    return found == components.end() ? Requirement::off : found->second;
}

}  // namespace pyobfuscator::native::cff
