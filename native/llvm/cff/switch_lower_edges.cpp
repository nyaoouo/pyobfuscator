#include "switch_lower_edges.hpp"
#include "cfg_origin.hpp"
#include "contribution_edges.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

void lower_switch_edges(llvm::Function &function, CfgOrigins *origins, ContributionEdgePlan *edges) {
    llvm::SmallVector<llvm::SwitchInst *, 4> switches;
    for (auto &block : function) {
        if (auto *branch = llvm::dyn_cast<llvm::SwitchInst>(block.getTerminator())) {
            switches.push_back(branch);
        }
    }

    for (auto *branch : switches) {
        auto &entry = function.getEntryBlock();
        llvm::IRBuilder<> setup(&*entry.getFirstInsertionPt());
        auto *condition_slot = setup.CreateAlloca(branch->getCondition()->getType(), nullptr,
                                                  "pyobf.switch.value");
        llvm::IRBuilder<> replacement(branch);
        replacement.CreateStore(branch->getCondition(), condition_slot);

        // Each check reloads the value: after flattening, a definition in the original
        // switch block cannot dominate the dispatcher-created check blocks.
        auto *next = branch->getDefaultDest();
        for (auto case_it = branch->case_end(); case_it != branch->case_begin();) {
            --case_it;
            auto *check = llvm::BasicBlock::Create(function.getContext(), "pyobf.switch.test",
                                                   &function);
            if (origins != nullptr) origins->set(*check, BlockRole::routing);
            llvm::IRBuilder<> test(check);
            auto *condition = test.CreateLoad(branch->getCondition()->getType(), condition_slot);
            test.CreateCondBr(test.CreateICmpEQ(condition, case_it->getCaseValue()),
                              case_it->getCaseSuccessor(), next);
            next = check;
        }
        auto *replacement_branch = replacement.CreateBr(next);
        replacement_branch->setMetadata("pyobf.cff.site", branch->getMetadata("pyobf.cff.site"));
        if (edges != nullptr) edges->switch_lowered(*branch, *condition_slot, *replacement_branch);
        branch->eraseFromParent();
    }
}

}  // namespace pyobfuscator::native::cff
