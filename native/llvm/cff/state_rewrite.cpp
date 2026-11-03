#include "cff.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"
#include "transition_rewrite.hpp"
#include "transition_layers.hpp"
#include "recipe.hpp"
#include "site_report.hpp"
#include "mutation_guard.hpp"
#include "preparation.hpp"
#include "reference_routes.hpp"
#include "call_frames.hpp"
#include "indexed_locals.hpp"
#include "hybrid_eh.hpp"
#include "hybrid_flow.hpp"
#include "path_fold_sites.hpp"
#include "contribution_gate.hpp"
#include "contribution_edges.hpp"
#include "contribution_edge_flow.hpp"
#include "bogus_controls.hpp"
#include "hybrid_scalar_bindings.hpp"

#include <cstdint>
#include <optional>
#include <vector>

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

namespace {

void verify_seal(const CfgSeal &seal, const llvm::Function &function,
                  const char *component) {
    if (const auto reason = seal.check(function); !reason.empty())
        llvm::report_fatal_error(llvm::StringRef(std::string(component) + ": " + reason));
}

std::string flatten_impl(llvm::Function &function, const ResolvedRecipe &recipe,
                          SiteCoverage &coverage) {
    if (function.isDeclaration()) {
        llvm::report_fatal_error("native CFF selected a declaration");
    }
    for (const auto &component : registered_components()) {
        if (recipe.enabled(component.name) && component.normalize != nullptr) {
            component.normalize(function, recipe, coverage);
            if (const auto reason = coverage.exceptional_origins().check(function); !reason.empty())
                return std::string(component.name) + ": " + reason;
        }
    }
    if (coverage.contribution_edges && coverage.contribution_edges->deferred())
        coverage.contribution_edges->instrument(function, coverage.origins());
    coverage.capture_normalized_cfg(function);
    if (const auto reason = validate_body_budget(function, recipe, true); !reason.empty()) return reason;
    std::vector<llvm::AllocaInst *> entry_allocations;
    for (auto &instruction : function.getEntryBlock())
        if (auto *allocation = llvm::dyn_cast<llvm::AllocaInst>(&instruction); allocation != nullptr && allocation->isStaticAlloca())
            entry_allocations.push_back(allocation);
    const auto normalized_blocks = function.size();
    pad_small_cfg(function, recipe.min_blocks, &coverage);
    coverage.shape_padding = function.size() - normalized_blocks;
    // Padding can add a new entry. Private invocation storage must remain an entry
    // allocation before SSA demotion considers values from the former entry.
    hoist_reference_storage(function);
    hoist_call_frame_storage(function);
    hoist_local_storage(function);
    // Padding and reference initialization may precede the original entry. Keep its
    // static objects dominating all later steps, including LLVM lifetime intrinsics.
    for (auto *allocation : entry_allocations)
        allocation->moveBefore(function.getEntryBlock().getFirstInsertionPt());
    std::optional<HybridEhPlan> eh;
    if (recipe.coverage == "hybrid-eh") eh = prepare_hybrid_eh(function, coverage);
    lower_cross_block_ssa(function, &coverage);
    if (coverage.contribution_edges)
        if (const auto reason = coverage.contribution_edges->before_lowering(function); !reason.empty()) return reason;
    lower_switches(function, &coverage);
    if (function.size() > recipe.max_body_blocks)
        return "normalized CFF scope exceeds max_body_blocks before state assignment";
    auto &entry = function.getEntryBlock();
    auto *split_at = entry.getTerminator();
    for (auto &instruction : entry) {
        if (!llvm::isa<llvm::AllocaInst>(instruction) &&
            !llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) {
            split_at = &instruction;
            break;
        }
    }
    auto *start = entry.splitBasicBlock(split_at, "pyobf.start");
    coverage.origins().set(*start, coverage.origins().get(entry));
    std::vector<llvm::BasicBlock *> bodies;
    for (auto &block : function) {
        if (&block != &entry && (!eh || !eh->boundaries.count(&block))) {
            bodies.push_back(&block);
        }
    }
    if (bodies.size() < 3) {
        llvm::report_fatal_error("native CFF needs at least three body blocks");
    }

    for (const auto &component : registered_components()) {
        if (recipe.enabled(component.name) && component.route != nullptr) {
            const CfgSeal seal(function);
            component.route(function, bodies, &coverage, recipe.seeds.at(component.name));
            verify_seal(seal, function, component.name);
        }
    }
    auto &context = function.getContext();
    llvm::IRBuilder<> setup(&*entry.getFirstInsertionPt());
    auto *state_slot = setup.CreateAlloca(setup.getInt32Ty(), nullptr, "pyobf.state");
    if (recipe.enabled("path-fold"))
        state_slot->setMetadata("pyobf.path-fold.root", llvm::MDNode::get(context, {}));
    std::vector<const llvm::BasicBlock *> excluded;
    if (eh) for (auto *body : eh->boundaries) excluded.push_back(body);
    if (const auto reason = prepare_components(function, state_slot, recipe, coverage, excluded); !reason.empty())
        return reason;
    if (const auto reason = validate_frame_completion(function); !reason.empty()) return reason;
    if (const auto reason = coverage.exceptional_origins().check(function); !reason.empty()) return reason;
    bodies.clear();
    if (coverage.contribution_edges)
        if (const auto reason = coverage.contribution_edges->verify_sources(function); !reason.empty()) return reason;
    for (auto &block : function)
        if (&block != &entry && (!eh || !eh->boundaries.count(&block))) bodies.push_back(&block);
    if (bodies.size() > recipe.max_body_blocks)
        return "prepared CFF bodies exceed max_body_blocks before state assignment";
    coverage.capture_body_roles(bodies);
    auto layout = build_state_layout(function, bodies, recipe.seeds.at("cfg"));
    TransitionLayers layers(function, state_slot, layout.transition_salt, plan_transition_layers(function, layout, recipe));
    BogusControls controls(function, layout, state_slot, coverage.bogus_controls,
        recipe.enabled("integer-literals") ? std::optional<std::uint32_t>(recipe.seeds.at("integer-literals")) : std::nullopt, &layers);
    std::optional<ContributionGateSeal> contribution_seal;
    if (recipe.enabled("runtime-contribution")) contribution_seal.emplace(function, layout, recipe, &layers, &controls);
    const TransitionBinding *binding = contribution_seal ? static_cast<const TransitionBinding *>(&*contribution_seal) : &controls;
    std::optional<HybridScalarBindings> scalar_bindings;
    if (eh && recipe.enabled("integer-literals")) {
        scalar_bindings.emplace(function, layout, state_slot, *binding, recipe.seeds.at("integer-literals"));
        binding = &*scalar_bindings;
    }
    std::optional<PathFoldSeal> fold_seal;
    if (recipe.enabled("path-fold")) {
        std::vector<InstructionSite> planned;
        for (const auto &site : discover_path_fold_sites(function, recipe))
            if (coverage.needs_site("path-fold", *site.instruction)) planned.push_back(site);
        fold_seal.emplace(function, layout, planned);
    }
    auto *dispatch = llvm::BasicBlock::Create(context, "pyobf.dispatch", &function);
    std::optional<HybridFlowSeal> flow;
    if (eh) flow.emplace(function, *eh, layout, state_slot, dispatch);
    std::optional<ContributionEdgeFlowSeal> edge_flow;
    if (recipe.enabled("runtime-contribution") && !eh) edge_flow.emplace(function, layout, state_slot, dispatch);
    for (const auto &component : registered_components()) {
        if (!recipe.enabled(component.name) || component.bind == nullptr) continue;
        const CfgSeal seal(function);
        for (auto *body : bodies)
            component.bind(*body, state_slot, layout.states[body],
                           recipe.seeds.at(component.name), &coverage);
        verify_seal(seal, function, component.name);
    }
    if (eh) if (const auto reason = bind_hybrid_eh(*eh, function, layout, state_slot, dispatch); !reason.empty())
        return reason;
    llvm::IRBuilder<> entry_builder(entry.getTerminator());
    entry_builder.CreateStore(entry_builder.getInt32(layout.states[bodies.front()]), state_slot);
    entry.getTerminator()->eraseFromParent();
    entry_builder.SetInsertPoint(&entry);
    entry_builder.CreateBr(dispatch);

    for (auto *body : bodies)
        if (auto *branch = llvm::dyn_cast<llvm::BranchInst>(body->getTerminator()))
            rewrite_normal_transition(*branch, state_slot, layout, recipe, coverage, dispatch);

    llvm::IRBuilder<> dispatcher(dispatch);
    auto *current = dispatcher.CreateLoad(dispatcher.getInt32Ty(), state_slot);
    if (recipe.enabled("path-fold"))
        current->setMetadata("pyobf.path-fold.dispatch", llvm::MDNode::get(context, {}));
    dispatcher.CreateBr(build_dispatch_tree(function, current, layout.sorted_leaves,
                                            layout.random_state));
    shuffle_body_layout(function, bodies, layout.random_state);
    coverage.applied_cfg();
    if (const auto reason = coverage.exceptional_origins().check(function); !reason.empty()) return reason;
    if (eh) if (const auto reason = verify_hybrid_eh(*eh, function); !reason.empty()) return reason;
    if (flow) if (const auto reason = flow->verify(function, binding); !reason.empty()) return reason;
    if (edge_flow) { if (const auto reason = edge_flow->verify(function, binding); !reason.empty()) return reason; }
    else if (!flow) if (const auto reason = binding->verify(function); !reason.empty()) return reason;
    if (coverage.contribution_edges)
        if (const auto reason = coverage.contribution_edges->bind_dispatch_states(layout); !reason.empty()) return reason;
    if (!layers.empty()) function.addFnAttr("pyobf.transition.layers.verified");
    if (!controls.empty()) function.addFnAttr("pyobf.bogus.controls.verified");
    if (coverage.contribution_edges) coverage.contribution_edges->verified();
    function.addFnAttr("pyobf.cff.transformed");
    if (const auto reason = validate_reference_routes(function); !reason.empty()) return reason;
    if (fold_seal) return fold_seal->verify(function);
    return validate_path_fold(function);
}

}  // namespace

void flatten(llvm::Function &function, unsigned seed) {
    const auto recipe = resolve_recipe({}, function.getName(), {}, "relative-tree", false,
                                       false, seed);
    stamp_site_provenance(function, "input");
    SiteCoverage coverage(function, recipe);
    if (const auto reason = flatten_impl(function, recipe, coverage); !reason.empty())
        llvm::report_fatal_error(llvm::StringRef(reason));
}

void flatten_deep(llvm::Function &function, unsigned seed) {
    const auto recipe = resolve_recipe({}, function.getName(), {}, "relative-tree-deep", true,
                                       false, seed);
    stamp_site_provenance(function, "input");
    SiteCoverage coverage(function, recipe);
    if (const auto reason = flatten_impl(function, recipe, coverage); !reason.empty())
        llvm::report_fatal_error(llvm::StringRef(reason));
}

std::string flatten_configured(llvm::Function &function, const ResolvedRecipe &recipe,
                                SiteCoverage &coverage) {
    return flatten_impl(function, recipe, coverage);
}

}  // namespace pyobfuscator::native::cff
