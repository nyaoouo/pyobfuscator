#include "call_preparation.hpp"
#include "site_report.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

unsigned bind_call_addresses(llvm::BasicBlock &body, llvm::Value *state_slot,
                              std::uint32_t expected_state, std::uint32_t, SiteCoverage *coverage) {
    unsigned count = 0;
    for (auto iterator = body.begin(); iterator != body.end();) {
        auto &instruction = *iterator++;
        if (auto *step = instruction.getMetadata("pyobf.prep.step")) {
            if (step->getNumOperands() != 2) llvm::report_fatal_error("invalid call preparation step");
            llvm::IRBuilder<> builder(body.getContext());
            instruction.setMetadata("pyobf.prep.step-bound", llvm::MDNode::get(body.getContext(), {
                step->getOperand(0).get(), step->getOperand(1).get(),
                llvm::ConstantAsMetadata::get(builder.getInt32(expected_state))}));
            instruction.setMetadata("pyobf.prep.step", nullptr);
        }
        if (const auto *anchor = instruction.getMetadata("pyobf.prep.anchor")) {
            if (coverage != nullptr) {
                coverage->applied("call-preparation", instruction);
                const auto *role = llvm::dyn_cast<llvm::MDString>(anchor->getOperand(1));
                coverage->record_type("call-preparation", role->getString());
            }
        }
        const auto *pending = instruction.getMetadata("pyobf.prep.pending");
        if (pending == nullptr) continue;
        auto *address = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction);
        if (address == nullptr) llvm::report_fatal_error("invalid prepared call frame address");
        auto *bound = emit_prepared_address(*address, state_slot, expected_state);
        if (coverage != nullptr) coverage->coalesce_instruction(*address, *bound);
        address->replaceAllUsesWith(bound);
        address->eraseFromParent();
        ++count;
    }
    return count;
}

}  // namespace pyobfuscator::native::cff
