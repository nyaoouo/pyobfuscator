#pragma once

#include <cstdint>
#include <string>

namespace llvm { class Function; class BasicBlock; class Value; class LoadInst; class StoreInst; class Instruction; }
namespace pyobfuscator::native::cff {
// Compiler-owned proof, never populated from retained IR metadata alone.
class TransitionBinding {
public:
    virtual ~TransitionBinding() = default;
    virtual std::string verify(const llvm::Function &) const = 0;
    virtual bool covers_unconditional(const llvm::BasicBlock &, std::uint32_t state,
        std::uint32_t normal_encoded) const = 0;
    virtual const llvm::Value *normal_encoded(const llvm::BasicBlock &, const llvm::Value *value) const { return value; }
    virtual bool owns_state_read(const llvm::LoadInst &) const { return false; }
    virtual bool owns_state_write(const llvm::StoreInst &) const { return false; }
    virtual bool preserves_terminal_operand(const llvm::Instruction &, unsigned, const llvm::Value *, const llvm::Value *) const { return false; }
};
}
