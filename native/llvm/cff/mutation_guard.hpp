#pragma once

#include <string>
#include <vector>

namespace llvm {
class BasicBlock;
class Function;
class Instruction;
}

namespace pyobfuscator::native::cff {

class CfgSeal {
public:
    explicit CfgSeal(const llvm::Function &function);
    std::string check(const llvm::Function &function) const;
    std::string check_definitions(const llvm::Function &function) const;

private:
    struct Block {
        const llvm::BasicBlock *identity;
        const llvm::Instruction *terminator;
        std::vector<const llvm::BasicBlock *> successors;
    };
    std::vector<Block> blocks_;
    std::vector<const llvm::Function *> definitions_;
};

}  // namespace pyobfuscator::native::cff
