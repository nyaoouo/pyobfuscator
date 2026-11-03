#include "cff.hpp"
#include "site_report.hpp"
#include "scalar_mask.hpp"

#include <cstdint>

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

bool eligible_integer_operand(const llvm::Instruction &instruction, unsigned index) {
    if (instruction.getMetadata("pyobf.ref.control") != nullptr ||
        instruction.getMetadata("pyobf.prep.control") != nullptr ||
        instruction.getMetadata("pyobf.local.control") != nullptr ||
        instruction.getMetadata("pyobf.archive.key-slot") != nullptr ||
        instruction.getMetadata("pyobf.archive.key-clear") != nullptr) return false;
    if (index == 1 && instruction.getMetadata("pyobf.cff.public-coefficient") != nullptr)
        return false;
    if (llvm::isa<llvm::BinaryOperator>(instruction) ||
        llvm::isa<llvm::ICmpInst>(instruction)) {
        return true;
    }
    if (llvm::isa<llvm::StoreInst>(instruction)) {
        return index == 0;
    }
    if (llvm::isa<llvm::ReturnInst>(instruction)) {
        return index == 0;
    }
    return llvm::isa<llvm::SelectInst>(instruction) && index != 0;
}

bool has_eligible_integer_constants(const llvm::Function &function) {
    for (const auto &block : function) {
        for (const auto &instruction : block) {
            for (unsigned index = 0; index < instruction.getNumOperands(); ++index) {
                if (eligible_integer_operand(instruction, index)) {
                    const auto *constant =
                        llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(index));
                    if (constant != nullptr && supported_scalar_integer(constant->getType())) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

std::vector<InstructionSite> discover_integer_sites(llvm::Function &function, const ResolvedRecipe &) {
    std::vector<InstructionSite> result;
    for (auto &block : function) for (auto &instruction : block) {
        for (unsigned index = 0; index < instruction.getNumOperands(); ++index) {
            if (!eligible_integer_operand(instruction, index)) continue;
            const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(index));
            if (constant != nullptr) result.push_back({&instruction, index,
                supported_scalar_integer(constant->getType()) ? std::string{} :
                "integer literal hiding supports scalar i1 through i128 operands"});
        }
    }
    return result;
}

unsigned hide_integer_constants(llvm::BasicBlock &body, llvm::Value *state_slot,
                                std::uint32_t expected_state, std::uint32_t salt,
                                SiteCoverage *coverage) {
    unsigned hidden = 0;
    for (auto iterator = body.begin(); iterator != body.end();) {
        auto &instruction = *iterator++;
        for (unsigned index = 0; index < instruction.getNumOperands(); ++index) {
            if (!eligible_integer_operand(instruction, index)) {
                continue;
            }
            auto *constant = llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(index));
            if (constant == nullptr || !supported_scalar_integer(constant->getType())) {
                continue;
            }
            if (coverage != nullptr) coverage->applied("integer-literals", instruction, index);
            llvm::IRBuilder<> builder(&instruction);
            const auto width = constant->getBitWidth();
            instruction.setOperand(index, emit_scalar_literal(builder, *constant, state_slot, expected_state, salt));
            if (coverage != nullptr) coverage->record_type("integer-literals", "i" + std::to_string(width));
            ++hidden;
        }
    }
    return hidden;
}

}  // namespace pyobfuscator::native::cff
