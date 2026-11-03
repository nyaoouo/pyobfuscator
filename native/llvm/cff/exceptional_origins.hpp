#pragma once

#include <string>
#include <vector>

namespace llvm { class Function; class InvokeInst; class BasicBlock; class LandingPadInst; class Constant; }

namespace pyobfuscator::native::cff {

class ExceptionalOrigins {
public:
    explicit ExceptionalOrigins(const llvm::Function &function);
    std::string replace(const llvm::InvokeInst &from, const llvm::InvokeInst &to);
    std::string check(const llvm::Function &function) const;

private:
    struct Edge { const llvm::InvokeInst *current; const llvm::BasicBlock *unwind; };
    struct Pad {
        const llvm::LandingPadInst *instruction;
        const llvm::BasicBlock *header;
        bool cleanup;
        std::vector<llvm::Constant *> clauses;
    };
    const llvm::Function *owner_;
    const llvm::Constant *personality_;
    std::vector<Edge> edges_;
    std::vector<Pad> pads_;
};

}  // namespace pyobfuscator::native::cff
