#include "transition_layers.hpp"
#include "transition_registry.hpp"
#include "recipe.hpp"
#include "state_layout.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
TransitionLayerDescription selected(const llvm::BranchInst &branch, const ResolvedRecipe &recipe,
    std::uint32_t state, std::uint32_t salt) {
    TransitionLayerDescription description{state, salt, instruction_provenance(branch), {}};
    for (const auto &component : registered_components()) {
        if (!recipe.enabled(component.name) || component.transition_model == nullptr ||
                (component.transition_selected != nullptr && !component.transition_selected(branch))) continue;
        if (component.transition != component.transition_model->emit || llvm::StringRef(component.name) != component.transition_model->name)
            llvm::report_fatal_error("transition composition registration differs from its emitter");
        description.models.push_back({component.transition_model, recipe.seeds.at(component.name),
            llvm::StringRef(component.name) == "reachable-junk" ? recipe.junk_rounds : 0});
    }
    return description;
}
}
TransitionLayerPlans plan_transition_layers(const llvm::Function &function, const StateLayout &layout, const ResolvedRecipe &recipe) {
    TransitionLayerPlans result;
    for (const auto &body : function) if (layout.states.contains(&body))
        if (const auto *branch = llvm::dyn_cast<llvm::BranchInst>(body.getTerminator())) {
            auto description = selected(*branch, recipe, layout.states.lookup(&body), layout.transition_salt);
            if (!description.models.empty()) result.emplace(&body, std::move(description));
        }
    return result;
}
llvm::MDNode *transition_layers_tag(const llvm::BranchInst &branch, const ResolvedRecipe &recipe,
    std::uint32_t state, std::uint32_t salt) {
    const auto description = selected(branch, recipe, state, salt);
    return description.models.empty() ? nullptr : describe_transition_layers(branch.getContext(), description);
}
}
