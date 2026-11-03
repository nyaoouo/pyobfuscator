#include "call_frames.hpp"

#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::string validate_frame_completion(const llvm::Function &function) {
    std::map<const llvm::MDNode *, const llvm::InvokeInst *> invokes;
    for (const auto &block : function) for (const auto &instruction : block)
        if (const auto *tag = instruction.getMetadata("pyobf.frame.invoke"))
            if (const auto *invoke = llvm::dyn_cast<llvm::InvokeInst>(&instruction))
                if (!invokes.emplace(tag, invoke).second) return "framed EH has multiple owning invokes";
    if (invokes.empty()) return {};
    llvm::DominatorTree dominance(const_cast<llvm::Function &>(function));
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto found = invokes.find(instruction.getMetadata("pyobf.frame.result"));
        if (found == invokes.end()) continue;
        const auto *invoke = found->second;
        if (!dominance.dominates(llvm::BasicBlockEdge(invoke->getParent(), invoke->getNormalDest()), &block))
            return "framed EH result is not guarded by normal completion before state assignment";
    }
    return {};
}

}  // namespace pyobfuscator::native::cff
