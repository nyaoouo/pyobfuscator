#include "cff.hpp"
#include "site_report.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

bool eligible_internal_call(const llvm::CallInst &call, const llvm::Function &function) {
    if (call.isMustTailCall() || call.hasOperandBundles()) {
        return false;
    }
    const auto *callee = call.getCalledFunction();
    return callee != nullptr && !callee->isDeclaration() && !callee->isIntrinsic() &&
           callee != &function;
}

bool has_eligible_internal_calls(const llvm::Function &function) {
    for (const auto &block : function) {
        for (const auto &instruction : block) {
            const auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
            if (call != nullptr && eligible_internal_call(*call, function)) {
                return true;
            }
        }
    }
    return false;
}

std::vector<InstructionSite> discover_internal_call_sites(llvm::Function &function,
                                                        const ResolvedRecipe &) {
    std::vector<InstructionSite> result;
    for (auto &block : function) for (auto &instruction : block) {
        auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
        const auto *callee = call == nullptr ? nullptr : call->getCalledFunction();
        if (callee != nullptr && !callee->isDeclaration() && !callee->isIntrinsic())
            result.push_back({call, 0, eligible_internal_call(*call, function) ? std::string{} :
                "recursive, musttail or operand-bundle call is not supported by this route"});
    }
    return result;
}

unsigned route_internal_calls(llvm::Function &function,
                              llvm::ArrayRef<llvm::BasicBlock *> bodies,
                              SiteCoverage *coverage, unsigned) {
    unsigned routed = 0;
    auto &entry = function.getEntryBlock();
    for (auto *body : bodies) {
        for (auto &instruction : *body) {
            auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
            if (call == nullptr || !eligible_internal_call(*call, function)) {
                continue;
            }
            auto *callee = call->getCalledFunction();
            if (coverage != nullptr) coverage->applied("internal-calls", *call);
            llvm::IRBuilder<> entry_builder(&*entry.getFirstInsertionPt());
            auto *slot = entry_builder.CreateAlloca(entry_builder.getPtrTy(), nullptr,
                                                    "pyobf.call.slot");
            llvm::IRBuilder<> initializer(entry.getTerminator());
            initializer.CreateStore(callee, slot)->setVolatile(true);
            llvm::IRBuilder<> caller(call);
            auto *target = caller.CreateLoad(caller.getPtrTy(), slot, "pyobf.call.target");
            target->setVolatile(true);
            call->setCalledOperand(target);
            ++routed;
        }
    }
    return routed;
}

}  // namespace pyobfuscator::native::cff
