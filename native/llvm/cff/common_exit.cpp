#include "recipe.hpp"
#include "site_report.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_exit_sites(llvm::Function &function,
                                                const ResolvedRecipe &) {
    std::vector<InstructionSite> sites;
    const auto ambiguous = duplicated_provenance(function);
    for (auto &block : function) {
        auto *result = llvm::dyn_cast<llvm::ReturnInst>(block.getTerminator());
        if (result == nullptr) continue;
        std::string reason;
        for (const auto &instruction : block)
            if (const auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
                call != nullptr && call->isMustTailCall())
                reason = "common-exit cannot move a musttail return";
        const auto *type = function.getReturnType();
        if (!type->isVoidTy() && (!type->isSized() || type->isVectorTy()))
            reason = "common-exit needs a fixed-size non-vector result";
        if (function.hasFnAttribute(llvm::Attribute::Naked))
            reason = "common-exit cannot add result storage to a naked function";
        if (ambiguous.count(instruction_provenance(*result)))
            reason = "common-exit has ambiguous duplicated return provenance";
        sites.push_back({result, 0, reason});
    }
    if (sites.size() < 2) sites.clear();
    unsigned admitted = 0;
    for (const auto &site : sites) admitted += site.reason.empty();
    if (admitted < 2) for (auto &site : sites) if (site.reason.empty())
        site.reason = "common-exit needs at least two compatible returns";
    return sites;
}

unsigned normalize_exits(llvm::Function &function, const ResolvedRecipe &recipe,
                          SiteCoverage &coverage) {
    const auto sites = discover_exit_sites(function, recipe);
    unsigned admitted = 0;
    for (const auto &site : sites) admitted += site.reason.empty();
    if (admitted < 2) return 0;
    auto *exit = llvm::BasicBlock::Create(function.getContext(), "pyobf.common.exit", &function);
    auto *type = function.getReturnType();
    llvm::AllocaInst *slot = nullptr;
    if (!type->isVoidTy()) {
        llvm::IRBuilder<> setup(&*function.getEntryBlock().getFirstInsertionPt());
        slot = setup.CreateAlloca(type, nullptr, "pyobf.result.slot");
    }
    llvm::IRBuilder<> finish(exit);
    if (slot == nullptr) finish.CreateRetVoid();
    else finish.CreateRet(finish.CreateLoad(type, slot, "pyobf.result"));
    for (const auto &site : sites) {
        if (!site.reason.empty()) continue;
        auto *result = llvm::cast<llvm::ReturnInst>(site.instruction);
        coverage.applied("common-exit", *result);
        llvm::IRBuilder<> builder(result);
        if (slot != nullptr) {
            auto *store = builder.CreateStore(result->getReturnValue(), slot);
            coverage.relocate_use("integer-literals", *result, 0, *store, 0);
            coverage.relocate_use("reference-routes", *result, 0, *store, 0);
            coverage.relocate_use("import-routes", *result, 0, *store, 0);
        }
        auto *branch = builder.CreateBr(exit);
        branch->setMetadata("pyobf.cff.site", result->getMetadata("pyobf.cff.site"));
        result->eraseFromParent();
    }
    coverage.normalized_returns += admitted;
    return admitted;
}

}  // namespace pyobfuscator::native::cff
