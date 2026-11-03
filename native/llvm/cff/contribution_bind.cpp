#include "contribution_gate.hpp"
#include "contribution_private.hpp"
#include "contribution_groups.hpp"
#include "path_fold.hpp"
#include "path_fold/value.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
bool contribution_transition_selected(const llvm::Instruction &instruction) {
    return instruction.getMetadata("pyobf.contribution.site") != nullptr;
}
llvm::Value *bind_contribution_transition(llvm::IRBuilder<> &builder, llvm::Value *normal,
    llvm::Value *, std::uint32_t state, std::uint32_t seed, const ResolvedRecipe &recipe) {
    if (recipe.contribution && recipe.contribution->schema >= 2)
        return bind_contribution_group_transition(builder, normal, state, seed, recipe);
    auto *body = builder.GetInsertBlock();
    llvm::CallInst *query = nullptr;
    for (auto &instruction : *body) if (instruction.getMetadata("pyobf.contribution.query")) {
        if (query != nullptr) llvm::report_fatal_error("contribution transition has multiple queries");
        query = llvm::dyn_cast<llvm::CallInst>(&instruction);
    }
    if (query == nullptr || !recipe.contribution) llvm::report_fatal_error("contribution transition lost its acquisition");
    const auto site = static_cast<std::uint32_t>(llvm::cast<llvm::ConstantInt>(query->getArgOperand(4))->getZExtValue());
    const auto salt = component_seed(seed, body->getParent()->getName(), "contribution-site:" + std::to_string(site));
    const auto expected = reference_contribution(*recipe.contribution, body->getParent()->getName(), site, state);
    const auto mask = path_fold::mix(expected ^ salt);
    std::uint32_t yes, no;
    bool conditional = false;
    llvm::Value *sealed;
    if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(normal)) {
        yes = no = static_cast<std::uint32_t>(constant->getZExtValue()) ^ mask;
        sealed = builder.getInt32(yes);
    } else if (auto *choice = llvm::dyn_cast<llvm::SelectInst>(normal)) {
        const auto *first = llvm::dyn_cast<llvm::ConstantInt>(choice->getTrueValue());
        const auto *second = llvm::dyn_cast<llvm::ConstantInt>(choice->getFalseValue());
        if (first == nullptr || second == nullptr) llvm::report_fatal_error("contribution needs unmodified constant transition arms");
        yes = static_cast<std::uint32_t>(first->getZExtValue()) ^ mask;
        no = static_cast<std::uint32_t>(second->getZExtValue()) ^ mask;
        sealed = builder.CreateSelect(choice->getCondition(), builder.getInt32(yes), builder.getInt32(no));
        conditional = true;
        if (!choice->use_empty()) llvm::report_fatal_error("contribution transition arms escaped before sealing");
        choice->eraseFromParent();
    } else llvm::report_fatal_error("contribution needs an original encoded transition");
    auto *actual_mask = emit_path_fold_word(builder, query, 0, salt);
    auto *encoded = builder.CreateXor(actual_mask, sealed);
    const auto &input = *recipe.contribution;
    llvm::SmallVector<llvm::Metadata *, 11> fields;
    for (auto number : {1u, site, state, salt, yes, no, std::uint32_t(conditional),
            input.routing, input.domain, input.owners.at(body->getParent()->getName().str()), input.source})
        fields.push_back(llvm::ConstantAsMetadata::get(builder.getInt32(number)));
    query->setMetadata("pyobf.contribution.query", llvm::MDNode::get(builder.getContext(), fields));
    body->getParent()->addFnAttr("pyobf.contribution.bound");
    return encoded;
}
}
