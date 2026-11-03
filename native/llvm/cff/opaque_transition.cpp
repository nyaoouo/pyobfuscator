#include "recipe.hpp"
#include "opaque_expression.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
llvm::Value *select_opaque_transition(llvm::IRBuilder<> &builder, llvm::Value *normal,
    llvm::Value *state_slot, std::uint32_t, std::uint32_t salt, const ResolvedRecipe &) {
    const auto *branch = builder.GetInsertBlock()->getTerminator();
    salt = component_seed(salt, branch->getFunction()->getName(), instruction_provenance(*branch));
    auto *predicate = emit_opaque_true(builder, state_slot, salt, salt % 3u);
    // Preserve the same late-pass grammar for literal and symbolic encoded inputs.
    auto *fake = builder.Insert(llvm::BinaryOperator::CreateXor(normal, builder.getInt32((salt ^ 0xb5297a4du) | 1u)));
    if ((salt >> 8) & 1u)
        return builder.CreateSelect(builder.CreateNot(predicate), fake, normal, "pyobf.opaque.choice");
    return builder.CreateSelect(predicate, normal, fake, "pyobf.opaque.choice");
}
}
