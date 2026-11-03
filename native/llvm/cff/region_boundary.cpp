#include "region_boundary.hpp"
#include "region_scope.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
RegionBoundarySeal::RegionBoundarySeal(const llvm::Function &function, const RegionScope &scope)
    : owner_(&function), entry_(scope.entry()), dummy_(llvm::BasicBlock::Create(function.getContext())) {
    for (const auto &body : function) {
        if (scope.contains(body)) continue;
        auto &records = outside_[&body];
        for (const auto &instruction : body) {
            Instruction record{&instruction, std::unique_ptr<llvm::Instruction, llvm::ValueDeleter>(instruction.clone()), {}, {}, {}};
            instruction.getAllMetadata(record.metadata);
            if (const auto *phi = llvm::dyn_cast<llvm::PHINode>(&instruction))
                for (unsigned index = 0; index != phi->getNumIncomingValues(); ++index) record.phi_blocks.push_back(phi->getIncomingBlock(index));
            for (unsigned index = 0; index != instruction.getNumOperands(); ++index) {
                auto *value = instruction.getOperand(index);
                record.operands.push_back(value);
                // Detached snapshots must not add CFG predecessors or spill users.
                llvm::Value *replacement;
                if (value->getType()->isLabelTy()) replacement = dummy_.get();
                else if (value->getType()->isTokenTy()) replacement = llvm::ConstantTokenNone::get(function.getContext());
                else if (value->getType()->isMetadataTy()) replacement = llvm::MetadataAsValue::get(function.getContext(), llvm::MDNode::get(function.getContext(), {}));
                else replacement = llvm::UndefValue::get(value->getType());
                record.operation->setOperand(index, replacement);
            }
            records.push_back(std::move(record));
        }
    }
}

std::string RegionBoundarySeal::verify(const llvm::Function &function, const llvm::BasicBlock &setup,
    const llvm::AllocaInst &state) const {
    if (&function != owner_) return "region boundary owner changed";
    std::set<const llvm::BasicBlock *> present;
    for (const auto &body : function) present.insert(&body);
    for (const auto &[body, records] : outside_) {
        if (!present.count(body)) return "region lost an outside body";
        std::vector<const llvm::Instruction *> actual;
        for (const auto &instruction : *body) if (&instruction != &state) actual.push_back(&instruction);
        if (actual.size() != records.size()) return "region added or erased outside instructions";
        for (unsigned index = 0; index != records.size(); ++index) {
            const auto &record = records[index];
            const auto *instruction = actual[index];
            if (instruction != record.identity || !instruction->isSameOperationAs(record.operation.get()))
                return "region changed an outside operation or flags";
            llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 4> metadata;
            instruction->getAllMetadata(metadata);
            if (metadata != record.metadata) return "region changed outside instruction metadata";
            for (unsigned operand = 0; operand != record.operands.size(); ++operand) {
                const auto *expected = record.operands[operand];
                if (instruction->isTerminator() && expected == entry_) expected = &setup;
                if (instruction->getOperand(operand) != expected) return "region changed an outside operand or admission route";
            }
            if (const auto *phi = llvm::dyn_cast<llvm::PHINode>(instruction))
                for (unsigned incoming = 0; incoming != record.phi_blocks.size(); ++incoming)
                    if (phi->getIncomingBlock(incoming) != record.phi_blocks[incoming]) return "region changed an outside PHI predecessor";
        }
    }
    return {};
}
}
