#include "recipe.hpp"
#include "block_split.hpp"
#include "site_report.hpp"
#include "contribution_edges.hpp"
#include "source_marker.hpp"
#include "site_provenance.hpp"

#include <algorithm>

#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {

bool counts_as_work(const llvm::Instruction &instruction) {
    if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
        if (const auto *target = call->getCalledFunction(); target != nullptr && source_marker_name(target->getName())) return false;
    return !instruction.isTerminator() &&
           !llvm::isa<llvm::PHINode, llvm::AllocaInst, llvm::DbgInfoIntrinsic>(instruction);
}

std::string boundary_reason(const llvm::Instruction &cut) {
    if (cut.isEHPad()) return "cannot split before an EH pad";
    for (const auto &instruction : *cut.getParent()) {
        if (&instruction == &cut) break;
        if (const auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
            call != nullptr && call->isMustTailCall())
            return "cannot split a musttail call/return sequence";
        if (instruction.getType()->isVoidTy() || instruction.getType()->isSized()) continue;
        for (const auto *user : instruction.users()) {
            const auto *use = llvm::dyn_cast<llvm::Instruction>(user);
            if (use != nullptr && use->getParent() == cut.getParent() &&
                (use == &cut || cut.comesBefore(use)))
                return "split would create an unsized cross-block SSA value";
        }
    }
    return {};
}

bool existing_boundary(const llvm::Instruction &instruction) {
    const auto *body = instruction.getParent();
    return body != &body->getParent()->getEntryBlock() && &instruction == &*body->getFirstNonPHIIt();
}

std::vector<InstructionSite> plan_splits(llvm::Function &function,
    const ResolvedRecipe &recipe, const SiteCoverage *coverage = nullptr,
    llvm::ArrayRef<RequestedSite> requests = {}) {
    std::vector<InstructionSite> sites;
    std::set<std::string> original;
    for (const auto &request : requests) if (request.component == "split-blocks") original.insert(request.id);
    for (auto &block : function) {
        unsigned work = 0;
        bool recorded_unsplittable = false;
        for (auto &instruction : block) {
            if (!counts_as_work(instruction)) continue;
            // Earlier source/frame normalization may reset a block's budget phase.
            // A retained original cut remains a request even below the new budget.
            if (work >= recipe.max_block_instructions ||
                    (!original.empty() && original.count(instruction_site_id(instruction, "split-blocks", 0))) ||
                    (coverage != nullptr && coverage->needs_site("split-blocks", instruction))) {
                const auto reason = boundary_reason(instruction);
                if (reason.empty()) {
                    sites.push_back({&instruction, 0, {}});
                    work = 0;
                    recorded_unsplittable = false;
                } else if (!recorded_unsplittable) {
                    sites.push_back({&instruction, 0, reason});
                    recorded_unsplittable = true;
                }
            }
            ++work;
        }
    }
    const auto splits = std::count_if(sites.begin(), sites.end(),
        [&](const InstructionSite &site) {
            return site.reason.empty() && (coverage == nullptr || !existing_boundary(*site.instruction));
        });
    if (std::max<std::size_t>(function.size() + splits, recipe.min_blocks) > recipe.max_body_blocks)
        for (auto &site : sites) if (site.reason.empty())
            site.reason = "split plan exceeds max_body_blocks";
    return sites;
}

}  // namespace

std::vector<InstructionSite> discover_split_sites(llvm::Function &function,
                                                 const ResolvedRecipe &recipe) {
    return plan_splits(function, recipe);
}

std::vector<InstructionSite> discover_requested_splits(llvm::Function &function,
    const ResolvedRecipe &recipe, llvm::ArrayRef<RequestedSite> requests) {
    // Archive preparation runs before SiteCoverage exists. Retained original cuts
    // must not be mistaken for optimizer loss when new work shifts the budget phase.
    return plan_splits(function, recipe, nullptr, requests);
}

unsigned split_blocks(llvm::Function &function, const ResolvedRecipe &recipe,
                       SiteCoverage &coverage) {
    const auto sites = plan_splits(function, recipe, &coverage);
    unsigned applied = 0, retained = 0;
    // Reverse order keeps each earlier cut in its original prefix. No instruction is cloned,
    // speculated or reordered, including volatile/atomic operations and calls.
    for (auto iterator = sites.rbegin(); iterator != sites.rend(); ++iterator) {
        if (!iterator->reason.empty()) continue;
        auto *instruction = iterator->instruction;
        coverage.applied("split-blocks", *instruction);
        auto *prefix = instruction->getParent();
        // A previous normalizer may already have put this exact cut at an existing
        // entry. Retain its coverage without manufacturing an empty prefix block.
        if (existing_boundary(*instruction)) { ++retained; continue; }
        auto *suffix = prefix->splitBasicBlock(instruction, "pyobf.real.split");
        coverage.origins().set(*suffix, coverage.origins().get(*prefix));
        if (coverage.contribution_edges)
            if (const auto reason = coverage.contribution_edges->completion_split(*prefix, *suffix); !reason.empty())
                llvm::report_fatal_error(llvm::StringRef(reason));
        ++applied;
    }
    coverage.real_splits += applied;
    coverage.preparation_metric("split-blocks", "retained_existing_cuts", retained);
    return applied;
}

std::string validate_body_budget(llvm::Function &function, const ResolvedRecipe &recipe,
                                  bool structural_finished) {
    if (!structural_finished &&
        (recipe.enabled("common-exit") || recipe.enabled("deduplicate-blocks"))) return {};
    std::size_t blocks = function.size();
    if (blocks > recipe.max_body_blocks) return structural_finished ?
        "normalized scope exceeds max_body_blocks" : "function exceeds max_body_blocks before normalization";
    if (!structural_finished && recipe.enabled("split-blocks"))
        for (const auto &site : discover_split_sites(function, recipe)) blocks += site.reason.empty();
    blocks = std::max<std::size_t>(blocks, recipe.min_blocks);
    for (const auto &block : function)
        if (const auto *branch = llvm::dyn_cast<llvm::SwitchInst>(block.getTerminator()))
            blocks += branch->getNumCases();
    return blocks > recipe.max_body_blocks ? "normalization/switch lowering exceeds max_body_blocks" : "";
}

}  // namespace pyobfuscator::native::cff
