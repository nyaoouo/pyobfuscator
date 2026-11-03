#include "hybrid_eh.hpp"

#include "cfg_origin.hpp"
#include "contribution_edges.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

HybridEhPlan prepare_hybrid_eh_edges(llvm::Function &function, CfgOrigins &origins, ContributionEdgePlan *edges) {
    HybridEhPlan plan;
    plan.personality = function.getPersonalityFn();
    for (auto &block : function) {
        if (auto *invoke = llvm::dyn_cast<llvm::InvokeInst>(block.getTerminator()))
            plan.invokes.push_back({invoke, invoke->getNormalDest(), invoke->getUnwindDest(), nullptr});
        if (auto *pad = llvm::dyn_cast<llvm::LandingPadInst>(&*block.getFirstNonPHIIt())) {
            HybridEhPlan::Pad record{pad, &block, nullptr, pad->isCleanup(), {}};
            for (unsigned i = 0; i < pad->getNumClauses(); ++i) record.clauses.push_back(pad->getClause(i));
            plan.pads.push_back(std::move(record));
        }
    }
    for (auto &edge : plan.invokes) {
        auto *source = edge.instruction->getParent();
        edge.gateway = llvm::BasicBlock::Create(function.getContext(), "pyobf.eh.normal", &function, edge.normal);
        llvm::IRBuilder<>(edge.gateway).CreateBr(edge.normal);
        edge.normal->replacePhiUsesWith(source, edge.gateway);
        edge.instruction->setNormalDest(edge.gateway);
        if (edges != nullptr) edges->invoke_lowered(*edge.instruction, *edge.gateway);
        origins.set(*edge.gateway, BlockRole::routing);
        plan.boundaries.insert(edge.gateway);
    }
    for (auto &pad : plan.pads) {
        pad.continuation = pad.header->splitBasicBlock(std::next(pad.instruction->getIterator()), "pyobf.eh.continuation");
        origins.set(*pad.continuation, origins.get(*pad.header));
        origins.set(*pad.header, BlockRole::routing);
        plan.boundaries.insert(pad.header);
    }
    llvm::IRBuilder<> setup(&*function.getEntryBlock().getFirstInsertionPt());
    plan.unwind_correction = setup.CreateAlloca(setup.getInt32Ty(), nullptr, "pyobf.eh.correction");
    return plan;
}

}  // namespace pyobfuscator::native::cff
