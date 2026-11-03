#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "llvm/IR/Instruction.h"

namespace llvm { class Function; class AllocaInst; class BasicBlock; class MDNode; }
namespace pyobfuscator::native::cff {
class RegionScope;
class RegionBoundarySeal {
public:
    RegionBoundarySeal(const llvm::Function &, const RegionScope &);
    std::string verify(const llvm::Function &, const llvm::BasicBlock &setup, const llvm::AllocaInst &state) const;
private:
    struct Instruction {
        const llvm::Instruction *identity;
        std::unique_ptr<llvm::Instruction, llvm::ValueDeleter> operation;
        std::vector<const llvm::Value *> operands;
        std::vector<const llvm::BasicBlock *> phi_blocks;
        llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 4> metadata;
    };
    const llvm::Function *owner_;
    const llvm::BasicBlock *entry_;
    std::unique_ptr<llvm::BasicBlock> dummy_;
    std::map<const llvm::BasicBlock *, std::vector<Instruction>> outside_;
};
}
