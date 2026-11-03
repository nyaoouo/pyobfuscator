#include "contribution_gate.hpp"
#include "contribution_private.hpp"
#include "contribution_groups.hpp"
#include "contribution_query.hpp"
#include "transition_layers.hpp"
#include "bogus_controls.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"
#include "path_fold/value.hpp"

#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
ContributionGateSeal::ContributionGateSeal(const llvm::Function &function, const StateLayout &layout,
    const ResolvedRecipe &recipe, const TransitionLayers *layers, const BogusControls *controls)
    : owner_(&function), transition_salt_(layout.transition_salt), layers_(layers), controls_(controls) {
    query_name_ = recipe.contribution && recipe.contribution->schema >= 3 ? "" :
        recipe.contribution && recipe.contribution->provider == "measured-scope-v1" ?
        "pyobf_native_measured_contribution_word_v1" : "pyobf_native_contribution_word_v1";
    for (const auto &body : function) for (const auto &instruction : body) {
        if (!instruction.getMetadata("pyobf.contribution.query")) continue;
        const auto &query = llvm::cast<llvm::CallInst>(instruction);
        const auto *branch = llvm::cast<llvm::BranchInst>(body.getTerminator());
        const auto site = static_cast<std::uint32_t>(llvm::cast<llvm::ConstantInt>(query.getArgOperand(4))->getZExtValue());
        const auto state = layout.states.lookup(&body);
        const auto salt = component_seed(recipe.seeds.at("runtime-contribution"), function.getName(),
            "contribution-site:" + std::to_string(site));
        const auto *group = recipe.contribution->schema >= 2 ? &contribution_source_group(*recipe.contribution, function.getName().str(), site) : nullptr;
        const auto value = group == nullptr ? reference_contribution(*recipe.contribution, function.getName(), site, state) :
            reference_contribution_group(*recipe.contribution, function.getName().str(), site, state);
        const auto seal = [&](unsigned edge) {
            return encode_delta(state, layout.states.lookup(branch->getSuccessor(edge)), layout.transition_salt) ^
                path_fold::mix(value ^ salt);
        };
        points_.push_back({&query, &body, const_cast<llvm::Value *>(query.getArgOperand(0)),
            site, state, seal(0), seal(branch->isConditional() ? 1 : 0),
            encode_delta(state, layout.states.lookup(branch->getSuccessor(0)), layout.transition_salt),
            encode_delta(state, layout.states.lookup(branch->getSuccessor(branch->isConditional() ? 1 : 0)), layout.transition_salt),
            branch->isUnconditional(), salt, {recipe.contribution->routing, recipe.contribution->domain,
                recipe.contribution->owners.at(function.getName().str()), group == nullptr ? recipe.contribution->source : group->binding.sources.front().spec.word_label}});
        if (group != nullptr) {
            auto &point = points_.back(); point.schema = recipe.contribution->schema;
            point.query_name = contribution_group_query_name(group->binding.sources.front().spec.provider, point.schema).str();
            point.group_fields = {group->domain, static_cast<std::uint32_t>(group->binding.sources.size())};
            for (const auto &source : group->binding.sources) {
                point.group_fields.push_back(source.spec.word_label); point.group_fields.push_back(source.encoding_tag);
                if (point.schema == 4) point.group_fields.push_back(source.spec.provider == "measured-scope-v1" ? 2u : 1u);
            }
            if (point.schema == 3) point.group_fields.push_back(point.query_name == "pyobf_native_measured_contribution_word_v1" ? 2u : 1u);
            for (auto *source : contribution_group_queries(body)) {
                point.group_queries.push_back(const_cast<llvm::CallInst *>(source));
                point.group_references.push_back(const_cast<llvm::Value *>(source->getArgOperand(0)));
                if (point.schema == 4) point.group_peer_references.push_back(const_cast<llvm::Value *>(source->getArgOperand(7)));
            }
        } else points_.back().query_name = query_name_;
    }
}
std::string ContributionGateSeal::verify(const llvm::Function &function) const {
    if (&function != owner_) return "contribution source owner changed";
    if (!query_name_.empty() && contribution_query_name(function) != query_name_)
        return "contribution source ABI differs from frozen provider";
    if (layers_ != nullptr) if (const auto reason = layers_->verify(function); !reason.empty()) return reason;
    if (const auto reason = validate_contribution_gates(function, layers_, controls_); !reason.empty()) return reason;
    std::set<const llvm::Instruction *> remaining;
    for (const auto &body : function) for (const auto &instruction : body) remaining.insert(&instruction);
    for (const auto &point : points_) {
        if (!remaining.count(point.query)) return "contribution lost a frozen source point";
        const auto *query = llvm::cast<llvm::CallInst>(point.query);
        if (query->getCalledFunction() == nullptr || query->getCalledFunction()->getName() != point.query_name)
            return "contribution query differs from frozen provider";
        if (query->getParent() != point.body) return "contribution source moved from its frozen body";
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(point.body->getTerminator());
        const auto *store = branch == nullptr ? nullptr : llvm::dyn_cast_or_null<llvm::StoreInst>(branch->getPrevNode());
        const auto *tag = store == nullptr ? nullptr : store->getMetadata("pyobf.contribution.transition");
        const auto *salt = tag == nullptr || tag->getNumOperands() != 1 ? nullptr :
            llvm::mdconst::dyn_extract<llvm::ConstantInt>(tag->getOperand(0));
        if (salt == nullptr || !salt->getType()->isIntegerTy(32) || salt->getZExtValue() != transition_salt_)
            return "contribution decoder salt differs from its frozen state layout";
        const auto *descriptor = query->getMetadata("pyobf.contribution.query");
        const auto word = [&](unsigned index) {
            return static_cast<std::uint32_t>(llvm::mdconst::extract<llvm::ConstantInt>(descriptor->getOperand(index))->getZExtValue());
        };
        if (word(0) != point.schema || word(3) != point.salt) return "contribution query identity differs from its frozen private source plan";
        for (unsigned index = 0; index != point.identity.size(); ++index)
            if (word(7 + index) != point.identity[index])
                return "contribution query identity differs from its frozen private source plan";
        if (point.schema >= 2) {
            if (descriptor->getNumOperands() != 11 + point.group_fields.size()) return "contribution group differs from its frozen source subset";
            for (unsigned index = 0; index != point.group_fields.size(); ++index)
                if (word(11 + index) != point.group_fields[index]) return "contribution group differs from its frozen source subset";
            const auto actual = contribution_group_queries(*point.body);
            if (actual.size() != point.group_queries.size()) return "contribution group lost its frozen acquisitions";
            for (unsigned index = 0; index != actual.size(); ++index)
                if (actual[index] != point.group_queries[index]) return "contribution group replaced or reordered a frozen acquisition";
            if (point.schema == 4) {
                if (actual.size() != point.group_references.size() || actual.size() != point.group_peer_references.size())
                    return "source-mixed reference inventory changed";
                for (unsigned index = 0; index != actual.size(); ++index) {
                    const auto expected = contribution_group_query_name(
                        word(13 + 3 * index + 2) == 2 ? "measured-scope-v1" : "owned-context-v1", 4);
                    if (actual[index]->getCalledFunction()->getName() != expected ||
                            actual[index]->arg_size() != 8 ||
                            actual[index]->getArgOperand(0) != point.group_references[index] ||
                            actual[index]->getArgOperand(7) != point.group_peer_references[index])
                        return "source-mixed query differs from frozen provider reference";
                }
            }
        }
        if (query->getParent() != point.body || point.lease == nullptr || query->getArgOperand(0) != point.lease ||
                word(1) != point.site || word(2) != point.state || word(4) != point.sealed_yes || word(5) != point.sealed_no)
            return "contribution binding differs from its frozen source, body state or target";
    }
    return {};
}
}
