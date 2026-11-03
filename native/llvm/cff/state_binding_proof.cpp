#include "state_binding_proof.hpp"
#include "scalar_proof.hpp"
#include "transition_proof.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
std::string verify_state_bindings(const llvm::Function &function, const llvm::AllocaInst *root,
    const std::map<const llvm::BasicBlock *, std::uint32_t> &states) {
    struct Tag { const char *name; unsigned state; bool read; };
    const Tag tags[]{
        {"pyobf.ref.state", 0, true}, {"pyobf.ref.bound", 4, false},
        {"pyobf.prep.state", 0, true}, {"pyobf.prep.bound", 3, false},
        {"pyobf.prep.step-bound", 2, false},
        {"pyobf.local.state", 0, true}, {"pyobf.local.bound", 3, false}};
    for (const auto &body : function) for (const auto &instruction : body) for (const auto &tag : tags)
        if (const auto *description = instruction.getMetadata(tag.name)) {
            const auto expected = states.find(&body);
            const auto *value = description->getNumOperands() > tag.state ?
                llvm::mdconst::dyn_extract<llvm::ConstantInt>(description->getOperand(tag.state)) : nullptr;
            if (expected == states.end() || value == nullptr || !value->getType()->isIntegerTy(32) ||
                    !scalar_constant(value, expected->second)) return "data binding differs from its frozen CFF body state";
            if (tag.read && !simple_state_read(llvm::dyn_cast<llvm::LoadInst>(&instruction), root, &body))
                return "data binding does not read its actual CFF state root";
        }
    return {};
}
}
