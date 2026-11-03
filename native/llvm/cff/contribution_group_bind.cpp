#include "contribution_groups.hpp"
#include "contribution_private.hpp"
#include "contribution_mix.hpp"
#include "contribution_query.hpp"
#include "recipe.hpp"
#include "path_fold.hpp"
#include "path_fold/value.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
llvm::Value *bind_contribution_group_transition(llvm::IRBuilder<> &builder, llvm::Value *normal,
    std::uint32_t state, std::uint32_t seed, const ResolvedRecipe &recipe) {
    auto *body = builder.GetInsertBlock();
    const auto calls = contribution_group_queries(*body);
    if (calls.empty()) llvm::report_fatal_error("contribution group lost its acquisition");
    auto *query = const_cast<llvm::CallInst *>(calls.front());
    const auto site = static_cast<std::uint32_t>(llvm::cast<llvm::ConstantInt>(query->getArgOperand(4))->getZExtValue());
    const auto owner = body->getParent()->getName().str();
    const auto &input = *recipe.contribution;
    const auto &group = contribution_source_group(input, owner, site);
    if (calls.size() != group.binding.sources.size()) llvm::report_fatal_error("contribution group acquisition count changed");
    for (unsigned index = 0; index != calls.size(); ++index) {
        const auto measured = group.binding.sources[index].spec.provider == "measured-scope-v1";
        const auto expected_helper = contribution_group_query_name(group.binding.sources[index].spec.provider, input.schema);
        if (calls[index]->getCalledFunction()->getName() != expected_helper)
            llvm::report_fatal_error("contribution group source provider changed");
    }
    const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(normal);
    if (constant == nullptr) llvm::report_fatal_error("contribution group requires an unconditional routing gateway");
    const auto salt = component_seed(seed, owner, "contribution-site:" + std::to_string(site));
    const auto sealed = static_cast<std::uint32_t>(constant->getZExtValue()) ^ path_fold::mix(reference_contribution_group(input, owner, site, state) ^ salt);
    llvm::SmallVector<llvm::Metadata *, 32> fields;
    const auto field = [&](std::uint32_t value) { fields.push_back(llvm::ConstantAsMetadata::get(builder.getInt32(value))); };
    for (auto value : {input.schema, site, state, salt, sealed, sealed, 0u, input.routing, input.domain,
            input.owners.at(owner), group.binding.sources.front().spec.word_label, group.domain,
            static_cast<std::uint32_t>(calls.size())}) field(value);
    std::vector<std::pair<std::uint32_t, std::uint32_t>> labels;
    std::vector<llvm::Value *> observed;
    for (unsigned index = 0; index != calls.size(); ++index) {
        const auto &source = group.binding.sources[index];
        labels.push_back({source.spec.word_label, source.encoding_tag});
        field(source.spec.word_label); field(source.encoding_tag);
        if (input.schema == 4) field(source.spec.provider == "measured-scope-v1" ? 2u : 1u);
        observed.push_back(const_cast<llvm::CallInst *>(calls[index]));
    }
    if (input.schema == 3) field(group.binding.sources.front().spec.provider == "measured-scope-v1" ? 2u : 1u);
    auto *actual = emit_contribution_mix(builder, plan_contribution_mix(group.domain, input.owners.at(owner), site, labels), observed);
    query->setMetadata("pyobf.contribution.query", llvm::MDNode::get(builder.getContext(), fields));
    body->getParent()->addFnAttr("pyobf.contribution.bound");
    return builder.CreateXor(emit_path_fold_word(builder, actual, 0, salt), builder.getInt32(sealed));
}
}
