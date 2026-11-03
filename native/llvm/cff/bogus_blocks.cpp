#include "bogus_blocks.hpp"

#include "opaque_expression.hpp"
#include "site_provenance.hpp"
#include "site_report.hpp"
#include "transition_sites.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::vector<llvm::Instruction *> select_bogus_sites(SiteCoverage &coverage, llvm::StringRef component, unsigned limit) {
    return select_prepared_sites(coverage, component, limit, [&](const llvm::Instruction &instruction) -> std::string {
        // Source gateways and frame/EH completions are indivisible routing contracts.
        // The existing normal/shape work remains available for actual bogus placements.
        if (coverage.transition_role(instruction) == BlockRole::routing)
            return "bogus placement cannot subdivide an owned routing boundary";
        return {};
    });
}

unsigned bogus_quota(const ResolvedRecipe &recipe, llvm::StringRef component) {
    if (!recipe.enabled("bogus-clones") || !recipe.enabled("bogus-synthesis"))
        return recipe.max_bogus_blocks;
    const auto clones = static_cast<unsigned>((std::uint64_t{recipe.max_bogus_blocks} *
                                               recipe.clone_percent + 99) / 100);
    return component == "bogus-clones" ? clones : recipe.max_bogus_blocks - clones;
}

BogusPlacement create_bogus_block(llvm::Instruction &anchor, llvm::StringRef component,
    SiteCoverage &coverage, llvm::Value *state, std::uint32_t seed) {
    auto *prefix = anchor.getParent();
    auto *function = prefix->getParent();
    auto *continuation = prefix->splitBasicBlock(&anchor, "pyobf.bogus.continue");
    coverage.origins().set(*continuation, coverage.origins().get(*prefix));
    auto *fake = llvm::BasicBlock::Create(function->getContext(), "pyobf.bogus.body",
                                          function, continuation);
    coverage.origins().set(*fake, BlockRole::decoy);
    llvm::IRBuilder<> fake_builder(fake);
    fake_builder.CreateBr(continuation);
    prefix->getTerminator()->eraseFromParent();
    llvm::IRBuilder<> guard_builder(prefix);
    auto *guard = guard_builder.CreateCondBr(guard_builder.getTrue(), continuation, fake);
    mark_transition(*guard, "pyobf.cff.routing-edge");
    mark_transition(*guard, "pyobf.cff." + component.str() + ".guard");
    coverage.relocate_use(component, anchor, 0, *guard, 0);
    coverage.plan_site(component, *guard);
    const auto provenance = instruction_provenance(*guard);
    const auto salt = component_seed(seed, function->getName(), provenance);
    llvm::IRBuilder<> predicate(guard);
    auto *condition = emit_opaque_true(predicate, state, salt, salt % 3);
    guard->setCondition(condition);
    coverage.bogus_controls.push_back({guard, continuation, fake, condition, nullptr, nullptr,
        component.str(), provenance, salt});
    ++coverage.decoy_blocks;
    return {guard, fake};
}

void mark_bogus_result(llvm::Value *value, llvm::Value *state, SiteCoverage &coverage) {
    auto *result = llvm::cast<llvm::Instruction>(value);
    mark_transition(*result, "pyobf.cff.bogus-result");
    for (auto &site : coverage.bogus_controls) if (site.decoy == result->getParent()) {
        if (site.result != nullptr) llvm::report_fatal_error("bogus control has duplicate owned work");
        site.result = result;
        llvm::IRBuilder<> builder(result->getParent()->getTerminator());
        site.work = builder.CreateStore(result, state);
        return;
    }
    llvm::report_fatal_error("bogus work has no compiler-owned control site");
}

unsigned bind_bogus_block(llvm::BasicBlock &body, llvm::Value *,
                           std::uint32_t, SiteCoverage *coverage,
                           llvm::StringRef component) {
    auto *branch = llvm::dyn_cast<llvm::BranchInst>(body.getTerminator());
    if (branch == nullptr) return 0;
    if (transition_marked(*branch, "pyobf.cff." + component.str() + ".guard")) {
        coverage->applied(component, *branch);
        return 1;
    }
    return 0;
}

}  // namespace pyobfuscator::native::cff
