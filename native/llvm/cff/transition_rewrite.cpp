#include "transition_rewrite.hpp"
#include "recipe.hpp"
#include "site_report.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"
#include "mutation_guard.hpp"
#include "contribution_gate.hpp"
#include "transition_layers.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
void rewrite_normal_transition(llvm::BranchInst &entry_branch, llvm::Value *state_slot,
    const StateLayout &layout, const ResolvedRecipe &recipe, SiteCoverage &coverage, llvm::BasicBlock *dispatch) {
    auto *branch = &entry_branch;
    auto *body = branch->getParent();
    auto &function = *body->getParent();
    auto &context = function.getContext();
    coverage.record_transition(*branch);
    for (unsigned index = 0; index < branch->getNumSuccessors(); ++index) {
        if (!layout.states.contains(branch->getSuccessor(index))) {
            llvm::report_fatal_error("native CFF branch escapes selected body");
        }
    }
    llvm::IRBuilder<> builder(branch);
    auto *current = builder.CreateLoad(builder.getInt32Ty(), state_slot);
    llvm::Value *encoded;
    if (branch->isConditional()) {
        const auto yes = encode_delta(layout.states.lookup(body),
                                      layout.states.lookup(branch->getSuccessor(0)),
                                      layout.transition_salt);
        const auto no = encode_delta(layout.states.lookup(body),
                                     layout.states.lookup(branch->getSuccessor(1)),
                                     layout.transition_salt);
        encoded = builder.CreateSelect(branch->getCondition(), builder.getInt32(yes),
                                       builder.getInt32(no));
    } else {
        const auto next = encode_delta(layout.states.lookup(body),
                                       layout.states.lookup(branch->getSuccessor(0)),
                                       layout.transition_salt);
        encoded = builder.getInt32(next);
    }
    auto *layer_description = transition_layers_tag(*branch, recipe, layout.states.lookup(body), layout.transition_salt);
    for (const auto &component : registered_components()) {
        if (!recipe.enabled(component.name) || component.transition == nullptr) continue;
        if (component.transition_selected != nullptr && !component.transition_selected(*branch)) continue;
        const CfgSeal seal(function);
        encoded = component.transition(builder, encoded, state_slot,
                                        layout.states.lookup(body), recipe.seeds.at(component.name), recipe);
        if (const auto reason = seal.check(function); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(std::string(component.name) + ": " + reason));
        coverage.applied(component.name, *branch);
    }
    auto *delta = decode_delta(builder, current, encoded, layout.transition_salt);
    auto *state_update = builder.CreateStore(builder.CreateAdd(current, delta), state_slot);
    if (layer_description != nullptr) state_update->setMetadata("pyobf.transition.layers", layer_description);
    if (contribution_transition_selected(*branch))
        state_update->setMetadata("pyobf.contribution.transition", llvm::MDNode::get(context,
            {llvm::ConstantAsMetadata::get(builder.getInt32(layout.transition_salt))}));
    auto *rewritten_branch = builder.CreateBr(dispatch);
    rewritten_branch->setMetadata("pyobf.cff.site", branch->getMetadata("pyobf.cff.site"));
    branch->eraseFromParent();
}
}
