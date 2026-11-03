#include "recipe.hpp"
#include "site_report.hpp"
#include "site_provenance.hpp"
#include "contribution_edges.hpp"
#include "dedup_alias.hpp"

#include <algorithm>
#include <map>
#include <set>

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {

using Correspondence = std::vector<std::pair<llvm::Instruction *, llvm::Instruction *>>;

struct Match {
    llvm::BasicBlock *donor;
    llvm::BasicBlock *leader;
    Correspondence instructions;
    std::string reason;
};

bool unstable_constant(const llvm::Value *value) {
    if (llvm::isa<llvm::UndefValue, llvm::PoisonValue>(value)) return true;
    const auto *constant = llvm::dyn_cast<llvm::Constant>(value);
    if (constant == nullptr || llvm::isa<llvm::GlobalValue>(constant)) return false;
    for (const auto &operand : constant->operands())
        if (unstable_constant(operand.get())) return true;
    return false;
}

std::vector<std::pair<unsigned, llvm::MDNode *>> semantic_metadata(const llvm::Instruction &instruction) {
    llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 8> values;
    instruction.getAllMetadataOtherThanDebugLoc(values);
    const auto provenance = instruction.getContext().getMDKindID("pyobf.cff.site");
    std::vector<std::pair<unsigned, llvm::MDNode *>> result;
    for (const auto &value : values) if (value.first != provenance) result.push_back(value);
    std::sort(result.begin(), result.end(), [](const auto &left, const auto &right) {
        return left.first < right.first;
    });
    return result;
}

std::vector<llvm::Instruction *> body_instructions(llvm::BasicBlock &block) {
    std::vector<llvm::Instruction *> result;
    for (auto &instruction : block)
        if (!llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) result.push_back(&instruction);
    return result;
}

bool equivalent(llvm::BasicBlock &donor, llvm::BasicBlock &leader, Correspondence &pairs) {
    auto original = body_instructions(donor);
    auto retained = body_instructions(leader);
    if (original.size() != retained.size()) return false;
    std::map<const llvm::Value *, llvm::Value *> values;
    for (unsigned index = 0; index < original.size(); ++index) {
        auto *from = original[index];
        auto *to = retained[index];
        if (from->getNumOperands() != to->getNumOperands() ||
            semantic_metadata(*from) != semantic_metadata(*to)) return false;
        auto *comparison = from->clone();
        for (unsigned operand = 0; operand < from->getNumOperands(); ++operand) {
            if (const auto found = values.find(from->getOperand(operand)); found != values.end())
                comparison->setOperand(operand, found->second);
        }
        const bool same = comparison->isIdenticalTo(to);
        comparison->deleteValue();
        if (!same) return false;
        pairs.emplace_back(from, to);
        values[from] = to;
    }
    return true;
}

std::string safety_reason(const Match &match, const std::set<std::string> &ambiguous) {
    if (match.donor->hasAddressTaken() || match.leader->hasAddressTaken())
        return "dedup does not merge address-taken blocks";
    if (match.donor->isEHPad() || match.leader->isEHPad())
        return "dedup does not merge EH pads";
    std::map<const llvm::Value *, const llvm::Value *> values;
    for (const auto &[from, to] : match.instructions) {
        for (const auto *instruction : {from, to}) {
            if (llvm::isa<llvm::PHINode, llvm::AllocaInst, llvm::CallBase, llvm::FenceInst,
                          llvm::AtomicRMWInst, llvm::AtomicCmpXchgInst, llvm::FreezeInst,
                          llvm::VAArgInst>(instruction))
                return "dedup excludes PHI/alloca/call/synchronization/freeze donors";
            if (instruction->getType()->isVectorTy()) return "dedup vector donors are not supported";
            if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(instruction);
                load != nullptr && (load->isVolatile() || load->isAtomic()))
                return "dedup excludes volatile or atomic loads";
            if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(instruction);
                store != nullptr && (store->isVolatile() || store->isAtomic()))
                return "dedup excludes volatile or atomic stores";
            for (const auto &operand : instruction->operands())
                if (unstable_constant(operand.get())) return "dedup excludes undef/poison operands";
            if (ambiguous.count(instruction_provenance(*instruction)))
                return "dedup has ambiguous duplicated site provenance";
        }
        values[from] = to;
    }
    for (auto *successor : llvm::successors(match.donor)) {
        if (successor == match.donor || successor == match.leader)
            return "dedup does not merge self-referential successor blocks";
        for (const auto &phi : successor->phis()) {
            const auto from_index = phi.getBasicBlockIndex(match.donor);
            const auto to_index = phi.getBasicBlockIndex(match.leader);
            if (from_index < 0 || to_index < 0) return "dedup successor PHI lacks a predecessor";
            const auto *from = phi.getIncomingValue(from_index);
            const auto *to = phi.getIncomingValue(to_index);
            const auto found = values.find(from);
            if ((found == values.end() ? from : found->second) != to)
                return "dedup successor PHI values differ";
        }
    }
    return {};
}

std::vector<Match> plan(llvm::Function &function, const ResolvedRecipe &recipe) {
    std::vector<Match> result;
    if (function.hasFnAttribute("pyobf.cff.transformed")) {
        result.push_back({&function.getEntryBlock(), nullptr, {}, "dedup refuses already state-bound code"});
        return result;
    }
    std::vector<llvm::BasicBlock *> leaders;
    const auto ambiguous = duplicated_provenance(function);
    unsigned comparisons = 0;
    for (auto &donor : function) {
        if (&donor == &function.getEntryBlock()) continue;
        Match selected{&donor, nullptr, {}, {}};
        bool matched = false;
        for (auto *leader : leaders) {
            if (comparisons++ >= recipe.max_dedup_comparisons) {
                result.push_back({&donor, nullptr, {},
                    "dedup comparison budget exhausted; remaining eligibility is unknown"});
                return result;
            }
            Match candidate{&donor, leader, {}, {}};
            if (!equivalent(donor, *leader, candidate.instructions)) continue;
            candidate.reason = safety_reason(candidate, ambiguous);
            if (!matched || candidate.reason.empty()) selected = std::move(candidate);
            matched = true;
            if (selected.reason.empty()) break;
        }
        if (matched) result.push_back(std::move(selected));
        if (!matched || !result.back().reason.empty()) leaders.push_back(&donor);
    }
    return result;
}

}  // namespace

std::vector<InstructionSite> discover_dedup_sites(llvm::Function &function,
                                                 const ResolvedRecipe &recipe) {
    std::vector<InstructionSite> result;
    for (const auto &match : plan(function, recipe))
        result.push_back({match.donor->getTerminator(), 0, match.reason});
    return result;
}

unsigned deduplicate_blocks(llvm::Function &function, const ResolvedRecipe &recipe,
                             SiteCoverage &coverage) {
    unsigned merged = 0;
    for (const auto &match : plan(function, recipe)) {
        if (!match.reason.empty()) continue;
        if (coverage.contribution_edges)
            if (const auto reason = coverage.contribution_edges->coalesce(
                    DedupAlias(*match.donor->getTerminator(), *match.leader->getTerminator())); !reason.empty()) {
                coverage.reject_site("deduplicate-blocks", *match.donor->getTerminator(), reason);
                continue;
            }
        coverage.applied("deduplicate-blocks", *match.donor->getTerminator());
        for (const auto &[from, to] : match.instructions) coverage.coalesce_instruction(*from, *to);
        std::set<llvm::BasicBlock *> successors;
        for (auto *successor : llvm::successors(match.donor)) successors.insert(successor);
        for (auto *successor : successors) for (auto &phi : successor->phis()) {
            for (auto index = phi.getBasicBlockIndex(match.donor); index >= 0;
                 index = phi.getBasicBlockIndex(match.donor))
                phi.removeIncomingValue(static_cast<unsigned>(index), false);
        }
        for (const auto &[from, to] : match.instructions)
            if (!from->getType()->isVoidTy()) from->replaceAllUsesWith(to);
        match.donor->replaceAllUsesWith(match.leader);
        match.donor->eraseFromParent();
        ++merged;
    }
    coverage.deduplicated_blocks += merged;
    return merged;
}

}  // namespace pyobfuscator::native::cff
