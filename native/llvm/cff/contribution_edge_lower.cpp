#include "contribution_edges.hpp"
#include "contribution_groups.hpp"
#include "contribution_private.hpp"
#include "contribution_query.hpp"

#include <algorithm>
#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
std::string ContributionEdgePlan::before_lowering(const llvm::Function &function) {
    if (&function != owner_) return "automatic edge owner changed";
    if (!failure_.empty()) return failure_;
    if (const auto reason = verify_aliases(); !reason.empty()) return reason;
    std::set<const llvm::SwitchInst *> seen;
    for (unsigned i = 0; i != edges_.size(); ++i) {
        const auto &edge = edges_[i];
        if (!edge.selected) continue;
        auto *term = llvm::dyn_cast_or_null<llvm::Instruction>(edge.terminator);
        if (!source_targets_gateway(edge))
            return "automatic original edge lost its selected gateway before lowering";
        auto *branch = llvm::dyn_cast<llvm::SwitchInst>(term);
        if (branch == nullptr || !seen.insert(branch).second) continue;
        Switch record;
        record.original = branch; record.condition = branch->getCondition();
        record.targets.push_back(branch->getDefaultDest());
        for (const auto &item : branch->cases()) {
            record.cases.push_back(item.getCaseValue()); record.targets.push_back(item.getCaseSuccessor());
        }
        switches_.push_back(std::move(record));
    }
    return {};
}
void ContributionEdgePlan::switch_lowered(const llvm::SwitchInst &original, llvm::AllocaInst &slot, llvm::BranchInst &replacement) {
    for (auto &record : switches_) {
        if (record.original != &original) continue;
        record.source_branch = &replacement; record.slot = &slot;
        const auto *store = llvm::dyn_cast_or_null<llvm::StoreInst>(replacement.getPrevNode());
        if (store == nullptr || store->getPointerOperand() != &slot || store->getValueOperand() != record.condition) {
            failure_ = "automatic switch lowering lost its original condition store"; return;
        }
        record.store = const_cast<llvm::StoreInst *>(store);
        auto *next = replacement.getSuccessor(0);
        for (unsigned index = 0; index != record.cases.size(); ++index) {
            auto *check = llvm::dyn_cast<llvm::BranchInst>(next->getTerminator());
            auto *compare = check == nullptr || !check->isConditional() ? nullptr : llvm::dyn_cast<llvm::ICmpInst>(check->getCondition());
            auto *read = compare == nullptr ? nullptr : llvm::dyn_cast<llvm::LoadInst>(compare->getOperand(0));
            if (compare == nullptr || compare->getPredicate() != llvm::CmpInst::ICMP_EQ ||
                    read == nullptr || read->getPointerOperand() != &slot || !read->isSimple() ||
                    compare->getOperand(1) != record.cases[index] || check->getSuccessor(0) != record.targets[index + 1]) {
                failure_ = "automatic switch lowering changed an original case route"; return;
            }
            record.checks.push_back(check); next = check->getSuccessor(1);
        }
        if (next != record.targets[0]) failure_ = "automatic switch lowering changed its original default route";
        return;
    }
}
std::string ContributionEdgePlan::verify_sources(const llvm::Function &function) const {
    if (&function != owner_) return "automatic edge owner changed";
    if (!failure_.empty()) return failure_;
    if (const auto reason = verify_aliases(); !reason.empty()) return reason;
    if (multiple_scopes_) for (const auto &anchor : anchors_) {
        const auto *reference = static_cast<llvm::Value *>(anchor.origin);
        if (reference == nullptr) return "multiple Scope anchor lost its frozen pointer";
        unsigned retained = 0;
        for (const auto &body : function) for (const auto &instruction : body) {
            const auto *query = llvm::dyn_cast<llvm::CallInst>(&instruction);
            const auto *site = query == nullptr || query->arg_size() != 7 ||
                !query->getMetadata("pyobf.contribution.query") ? nullptr :
                llvm::dyn_cast<llvm::ConstantInt>(query->getArgOperand(4));
            if (site == nullptr || site->getZExtValue() != anchor.site) continue;
            if (contribution_edge_reference_origin(query->getArgOperand(0), const_cast<llvm::Function &>(function)) != reference ||
                    query->getCalledFunction() == nullptr ||
                    query->getCalledFunction()->getName() != "pyobf_native_measured_contribution_word_v1")
                return "multiple Scope anchor query differs from its frozen pointer";
            ++retained;
        }
        if (retained != 1) return "multiple Scope anchor query is absent or duplicated";
    }
    for (unsigned i = 0; i != edges_.size(); ++i) {
        const auto &edge = edges_[i];
        if (!edge.selected) continue;
        const auto *gateway = llvm::dyn_cast_or_null<llvm::BasicBlock>(edge.gateway);
        const auto *exit = gateway == nullptr ? nullptr : llvm::dyn_cast<llvm::BranchInst>(gateway->getTerminator());
        if (exit == nullptr || !exit->isUnconditional() || exit->getSuccessor(0) != edge.target)
            return "automatic edge gateway no longer precedes its original destination";
        unsigned queries = 0;
        const auto *reference = multiple_scopes_ ? static_cast<llvm::Value *>(edge.reference) : static_cast<llvm::Value *>(lease_);
        if (reference == nullptr) return "automatic edge lost its frozen Scope reference";
        if (multiple_scopes_) {
            const auto anchor = std::find_if(anchors_.begin(), anchors_.end(),
                [&](const ContributionEdgeAnchor &entry) { return entry.site == edge.reference_site; });
            if (anchor == anchors_.end() || anchor->origin != edge.reference)
                return "automatic edge differs from its frozen Scope anchor";
        }
        if (source_mixed_) {
            const auto *group = private_->group(function.getName().str(), edge.label);
            const auto acquired = contribution_group_queries(*gateway);
            if (group == nullptr || acquired.size() != group->binding.sources.size())
                return "source-mixed original edge lost its complete source group";
            unsigned primaries = 0;
            for (unsigned index = 0; index != acquired.size(); ++index) {
                const auto *query = acquired[index];
                const auto &source = group->binding.sources[index];
                const bool measured = source.spec.provider == "measured-scope-v1";
                const auto *site = query->arg_size() == 8 ?
                    llvm::dyn_cast<llvm::ConstantInt>(query->getArgOperand(4)) : nullptr;
                const auto *word = query->arg_size() == 8 ?
                    llvm::dyn_cast<llvm::ConstantInt>(query->getArgOperand(5)) : nullptr;
                if (query->getCalledFunction() == nullptr ||
                        query->getCalledFunction()->getName() !=
                            contribution_group_query_name(source.spec.provider, 4) ||
                        site == nullptr || site->getZExtValue() != edge.label ||
                        word == nullptr || word->getZExtValue() != source.spec.word_label ||
                        query->getArgOperand(0) != (measured ? static_cast<llvm::Value *>(measured_) : reference) ||
                        query->getArgOperand(7) != (measured ? reference : static_cast<llvm::Value *>(measured_)))
                    return "source-mixed original edge query lost frozen provider, source or identity";
                if (query->getMetadata("pyobf.contribution.query")) ++primaries;
            }
            if (primaries != 1) return "source-mixed original edge lacks one group primary";
            if (!source_targets_gateway(edge))
                return "automatic original branch bypasses its selected gateway";
            continue;
        }
        for (const auto &instruction : *gateway) {
            if (instruction.getMetadata("pyobf.contribution.query") == nullptr) continue;
            const auto *query = llvm::dyn_cast<llvm::CallInst>(&instruction);
            const auto *label = query == nullptr || query->arg_size() != 7 ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(query->getArgOperand(4));
            if (label == nullptr || label->getZExtValue() != edges_[canonical_[i]].label || query->getArgOperand(0) != reference)
                return "automatic edge query lost its frozen source or identity";
            ++queries;
        }
        if (queries != 1) return "automatic edge has no unique leased query";
        if (const auto *term = llvm::dyn_cast_or_null<llvm::Instruction>(edge.terminator)) {
            if (!source_targets_gateway(edge))
                return "automatic original branch bypasses its selected gateway";
        } else {
            bool lowered = false;
            for (const auto &record : switches_) if (record.original == edge.origin) lowered |= record.source_branch != nullptr;
            if (!lowered) return "automatic original source vanished without a verified lowering";
        }
    }
    for (const auto &record : switches_) {
        const auto *store = llvm::dyn_cast_or_null<llvm::StoreInst>(record.store);
        const auto *branch = llvm::dyn_cast_or_null<llvm::BranchInst>(record.source_branch);
        if (store == nullptr || branch == nullptr || !branch->isUnconditional() || store->getPointerOperand() != record.slot ||
                !store->isSimple() || store->getValueOperand() != record.condition || record.checks.size() != record.cases.size())
            return "automatic lowered switch source changed";
        const llvm::BasicBlock *next = branch->getSuccessor(0);
        std::set<const llvm::LoadInst *> reads;
        for (unsigned index = 0; index != record.checks.size(); ++index) {
            const auto *check = llvm::dyn_cast_or_null<llvm::BranchInst>(record.checks[index]);
            const auto *compare = check == nullptr || !check->isConditional() ? nullptr : llvm::dyn_cast<llvm::ICmpInst>(check->getCondition());
            const auto *read = compare == nullptr ? nullptr : llvm::dyn_cast<llvm::LoadInst>(compare->getOperand(0));
            if (check == nullptr || check->getParent() != next || compare == nullptr ||
                    compare->getPredicate() != llvm::CmpInst::ICMP_EQ || compare->getOperand(1) != record.cases[index] ||
                    read == nullptr || !read->isSimple() || read->getPointerOperand() != record.slot ||
                    check->getSuccessor(0) != record.targets[index + 1]) return "automatic lowered switch case changed";
            next = check->getSuccessor(1);
            reads.insert(read);
        }
        if (next != record.targets[0]) return "automatic lowered switch default changed";
        const auto *slot = llvm::dyn_cast_or_null<llvm::AllocaInst>(record.slot);
        if (slot == nullptr || slot->getParent() != &function.getEntryBlock()) return "automatic switch value storage changed";
        for (const auto *user : slot->users()) {
            if (user == store) continue;
            const auto *read = llvm::dyn_cast<llvm::LoadInst>(user);
            if (read == nullptr || !reads.count(read)) return "automatic switch value storage has an extra writer or escape";
        }
    }
    return {};
}
}
