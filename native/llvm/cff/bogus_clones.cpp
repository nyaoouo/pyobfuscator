#include "bogus_blocks.hpp"

#include "junk_expression.hpp"
#include "site_provenance.hpp"
#include "site_report.hpp"
#include "transition_sites.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {

using Donor = std::vector<llvm::BinaryOperator *>;

Donor safe_donor(llvm::Function &function, unsigned limit, const SiteCoverage *coverage = nullptr) {
    for (auto &block : function) {
        if (coverage != nullptr && coverage->origins().get(block) == BlockRole::decoy) continue;
        Donor result;
        for (auto &instruction : block) {
            auto *binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
            if (binary == nullptr || !binary->getType()->isIntegerTy(32)) continue;
            switch (binary->getOpcode()) {
            case llvm::Instruction::Add: case llvm::Instruction::Sub: case llvm::Instruction::Mul:
            case llvm::Instruction::And: case llvm::Instruction::Or: case llvm::Instruction::Xor: break;
            default: continue;
            }
            bool safe = true, live = false;
            for (auto *operand : binary->operand_values()) {
                bool prior = false;
                for (auto *candidate : result) prior |= operand == candidate;
                safe &= llvm::isa<llvm::Argument>(operand) || llvm::isa<llvm::ConstantInt>(operand) || prior;
                live |= llvm::isa<llvm::Argument>(operand) || prior;
            }
            if (safe && live) result.push_back(binary);
            if (result.size() == limit) break;
        }
        if (!result.empty()) return result;
    }
    return {};
}

}  // namespace

std::vector<InstructionSite> discover_bogus_clone_sites(llvm::Function &function,
                                                        const ResolvedRecipe &recipe) {
    auto sites = discover_transition_sites(function, bogus_quota(recipe, "bogus-clones"),
                                            recipe.seeds.at("bogus-clones"));
    if (safe_donor(function, recipe.max_clone_instructions).empty())
        for (auto &site : sites) site.reason = "no self-contained wrapping i32 donor";
    return sites;
}

unsigned prepare_bogus_clones(llvm::Function &function, llvm::Value *state_slot,
                               const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    const auto quota = bogus_quota(recipe, "bogus-clones");
    const auto sites = select_bogus_sites(coverage, "bogus-clones", quota);
    const auto donor = safe_donor(function, recipe.max_clone_instructions, &coverage);
    coverage.preparation_metric("bogus-clones", "quota", quota);
    coverage.preparation_metric("bogus-clones", "donor_instructions", donor.size());
    if (donor.empty()) {
        for (auto *site : sites)
            coverage.reject_site("bogus-clones", *site, "no self-contained wrapping i32 donor");
        coverage.preparation_metric("bogus-clones", "unavailable_allocations", sites.size());
        return 0;
    }
    for (auto *site : sites) {
        const auto placed = create_bogus_block(*site, "bogus-clones", coverage, state_slot, recipe.seeds.at("bogus-clones"));
        const auto salt = component_seed(recipe.seeds.at("bogus-clones"), function.getName(),
                                          instruction_provenance(*placed.guard));
        llvm::IRBuilder<> builder(placed.body->getTerminator());
        auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.clone.state");
        std::map<llvm::Value *, llvm::Value *> mapped;
        const auto operand = [&](llvm::Value *value) -> llvm::Value * {
            if (llvm::isa<llvm::ConstantInt>(value)) return value;
            if (const auto found = mapped.find(value); found != mapped.end()) return found->second;
            auto *argument = llvm::cast<llvm::Argument>(value);
            return mapped[value] = builder.CreateXor(state, builder.getInt32(
                salt + argument->getArgNo() * 0x9e3779b9u), "pyobf.clone.input");
        };
        for (auto *binary : donor) {
            // Build fresh wrapping operations: do not copy nsw/nuw/exact flags or site IDs.
            mapped[binary] = builder.CreateBinOp(binary->getOpcode(), operand(binary->getOperand(0)),
                                                  operand(binary->getOperand(1)), "pyobf.clone.value");
        }
        mark_bogus_result(emit_junk_mix(builder, mapped.at(donor.back()), salt, 1), state_slot, coverage);
        mark_transition(*placed.body->getTerminator(), "pyobf.cff.bogus-clones.work");
        std::vector<llvm::Instruction *> sources(donor.begin(), donor.end());
        coverage.record_donor("bogus-clones", *placed.guard, sources);
        ++coverage.bogus_clone_blocks;
        coverage.cloned_instructions += donor.size();
    }
    coverage.preparation_metric("bogus-clones", "selected_blocks", sites.size());
    return sites.size();
}

unsigned bind_bogus_clones(llvm::BasicBlock &body, llvm::Value *state_slot, std::uint32_t,
                            std::uint32_t salt, SiteCoverage *coverage) {
    return bind_bogus_block(body, state_slot, salt, coverage, "bogus-clones");
}

}  // namespace pyobfuscator::native::cff
