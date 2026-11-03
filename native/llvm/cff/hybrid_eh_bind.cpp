#include "hybrid_eh.hpp"

#include "state_layout.hpp"
#include "transition_encode.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::string verify_hybrid_eh(const HybridEhPlan &plan, const llvm::Function &function) {
    if (!function.hasPersonalityFn() || function.getPersonalityFn() != plan.personality)
        return "hybrid-eh personality changed";
    for (const auto &edge : plan.invokes)
        if (edge.instruction->getFunction() != &function || edge.instruction->getUnwindDest() != edge.unwind ||
            edge.instruction->getNormalDest() != edge.gateway)
            return "hybrid-eh invoke boundary changed";
    for (const auto &pad : plan.pads) {
        if (pad.instruction->getParent() != pad.header || !pad.header->isLandingPad() ||
            pad.instruction->isCleanup() != pad.cleanup || pad.instruction->getNumClauses() != pad.clauses.size())
            return "hybrid-eh landingpad contract changed";
        for (unsigned i = 0; i < pad.clauses.size(); ++i)
            if (pad.instruction->getClause(i) != pad.clauses[i]) return "hybrid-eh landingpad clause changed";
    }
    return {};
}

std::string bind_hybrid_eh(HybridEhPlan &plan, llvm::Function &function,
                           const StateLayout &layout, llvm::Value *state_slot,
                           llvm::BasicBlock *dispatch) {
    if (const auto reason = verify_hybrid_eh(plan, function); !reason.empty()) return reason;
    const auto transition = [&](llvm::BasicBlock *gate, llvm::Value *encoded) {
        auto *branch = llvm::cast<llvm::BranchInst>(gate->getTerminator());
        llvm::IRBuilder<> builder(branch);
        auto *current = builder.CreateLoad(builder.getInt32Ty(), state_slot);
        auto *delta = decode_delta(builder, current, encoded, layout.transition_salt);
        builder.CreateStore(builder.CreateAdd(current, delta), state_slot);
        builder.CreateBr(dispatch);
        branch->eraseFromParent();
    };
    for (auto &edge : plan.invokes) {
        llvm::BasicBlock *continuation = nullptr;
        for (const auto &pad : plan.pads) if (pad.header == edge.unwind) continuation = pad.continuation;
        if (!layout.states.contains(edge.instruction->getParent()) || !layout.states.contains(edge.normal) ||
            continuation == nullptr || !layout.states.contains(continuation))
            return "hybrid-eh gateway has no final body state";
        const auto source = layout.states.lookup(edge.instruction->getParent());
        llvm::IRBuilder<> arm(edge.instruction);
        arm.CreateStore(arm.getInt32(encode_delta(source, layout.states.lookup(continuation), layout.transition_salt)),
                        plan.unwind_correction);
        transition(edge.gateway, arm.getInt32(encode_delta(source, layout.states.lookup(edge.normal), layout.transition_salt)));
    }
    for (const auto &pad : plan.pads) {
        llvm::IRBuilder<> builder(pad.header->getTerminator());
        transition(pad.header, builder.CreateLoad(builder.getInt32Ty(), plan.unwind_correction));
    }
    return verify_hybrid_eh(plan, function);
}

}  // namespace pyobfuscator::native::cff
