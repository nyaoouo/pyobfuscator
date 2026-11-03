#include "region.hpp"
#include "region_scope.hpp"
#include "region_boundary.hpp"
#include "cff.hpp"
#include "recipe.hpp"
#include "site_report.hpp"
#include "preparation.hpp"
#include "mutation_guard.hpp"
#include "state_layout.hpp"
#include "transition_rewrite.hpp"
#include "contribution_gate.hpp"
#include "contribution_edges.hpp"
#include "contribution_edge_flow.hpp"

#include <optional>

#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
std::string flatten_region_configured(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    if (!recipe.region_scope) return "region pipeline has no selected scope";
    auto &scope = *recipe.region_scope;
    if (const auto reason = validate_relative_tree_region(function, scope.entry_name(), scope.exit_name()); !reason.empty()) return reason;
    const RegionBoundarySeal boundary(function, scope);
    for (const auto &component : registered_components()) {
        if (!recipe.enabled(component.name) || component.normalize == nullptr) continue;
        component.normalize(function, recipe, coverage);
        if (const auto reason = coverage.exceptional_origins().check(function); !reason.empty()) return reason;
    }
    coverage.capture_normalized_cfg(function);
    auto *entry = scope.entry(); auto *exit = scope.exit();
    auto *setup = llvm::BasicBlock::Create(function.getContext(), "pyobf.region.setup", &function, entry);
    coverage.origins().set(*setup, BlockRole::routing);
    std::vector<llvm::BasicBlock *> external;
    for (auto *body : llvm::predecessors(entry)) if (!scope.contains(*body)) external.push_back(body);
    for (auto *body : external) {
        auto *term = body->getTerminator();
        for (unsigned index = 0; index != term->getNumSuccessors(); ++index)
            if (term->getSuccessor(index) == entry) term->setSuccessor(index, setup);
    }
    llvm::IRBuilder<>(setup).CreateBr(entry);
    llvm::IRBuilder<> allocation(&*function.getEntryBlock().getFirstInsertionPt());
    auto *state = allocation.CreateAlloca(allocation.getInt32Ty(), nullptr, "pyobf.region.state");
    if (coverage.contribution_edges)
        if (const auto reason = coverage.contribution_edges->before_lowering(function); !reason.empty()) return reason;
    if (const auto reason = prepare_components(function, state, recipe, coverage); !reason.empty()) return reason;
    if (coverage.contribution_edges)
        if (const auto reason = coverage.contribution_edges->verify_sources(function); !reason.empty()) return reason;
    auto bodies = scope.bodies(function);
    if (bodies.size() + 1 > recipe.max_body_blocks) return "prepared region exceeds max_body_blocks";
    auto *exit_leaf = llvm::BasicBlock::Create(function.getContext(), "pyobf.region.exit", &function);
    llvm::IRBuilder<>(exit_leaf).CreateBr(exit);
    coverage.origins().set(*exit_leaf, BlockRole::routing);
    for (auto *body : bodies) {
        auto *term = body->getTerminator();
        for (unsigned index = 0; index != term->getNumSuccessors(); ++index)
            if (term->getSuccessor(index) == exit) term->setSuccessor(index, exit_leaf);
    }
    bodies.push_back(exit_leaf);
    coverage.capture_body_roles(bodies);
    auto layout = build_state_layout(function, bodies, recipe.seeds.at("cfg"));
    std::optional<ContributionGateSeal> gates;
    if (recipe.enabled("runtime-contribution")) gates.emplace(function, layout, recipe);
    auto *dispatch = llvm::BasicBlock::Create(function.getContext(), "pyobf.region.dispatch", &function);
    const ContributionEdgeFlowSeal flow(function, layout, state, dispatch, {setup, exit_leaf, exit});
    for (const auto &component : registered_components()) {
        if (!recipe.enabled(component.name) || component.bind == nullptr) continue;
        const CfgSeal seal(function);
        for (auto *body : bodies) if (body != exit_leaf)
            component.bind(*body, state, layout.states[body], recipe.seeds.at(component.name), &coverage);
        if (const auto reason = seal.check(function); !reason.empty()) return reason;
    }
    auto *old = setup->getTerminator(); llvm::IRBuilder<> initialize(old);
    initialize.CreateStore(initialize.getInt32(layout.states[entry]), state); initialize.CreateBr(dispatch); old->eraseFromParent();
    for (auto *body : bodies) if (body != exit_leaf)
        rewrite_normal_transition(*llvm::cast<llvm::BranchInst>(body->getTerminator()), state, layout, recipe, coverage, dispatch);
    llvm::IRBuilder<> tree(dispatch);
    auto *current = tree.CreateLoad(tree.getInt32Ty(), state);
    tree.CreateBr(build_dispatch_tree(function, current, layout.sorted_leaves, layout.random_state));
    if (const auto reason = flow.verify(function, gates ? &*gates : nullptr); !reason.empty()) return reason;
    if (const auto reason = boundary.verify(function, *setup, *state); !reason.empty()) return reason;
    if (const auto reason = coverage.exceptional_origins().check(function); !reason.empty()) return reason;
    if (coverage.contribution_edges) coverage.contribution_edges->verified();
    coverage.applied_cfg();
    function.addFnAttr("pyobf.cff.transformed");
    function.addFnAttr("pyobf.region.verified");
    return {};
}
}
