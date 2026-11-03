#include "recipe.hpp"
#include "junk_expression.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
llvm::Value *apply_reachable_junk(llvm::IRBuilder<> &builder, llvm::Value *normal,
    llvm::Value *state_slot, std::uint32_t expected_state, std::uint32_t salt, const ResolvedRecipe &recipe) {
    const auto *branch = builder.GetInsertBlock()->getTerminator();
    salt = component_seed(salt, branch->getFunction()->getName(), instruction_provenance(*branch));
    auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.junk.state");
    auto *mixed = emit_junk_mix(builder, state, salt, recipe.junk_rounds);
    const auto expected = junk_mix_value(expected_state, salt, recipe.junk_rounds);
    auto *correction = builder.CreateXor(mixed, builder.getInt32(expected), "pyobf.junk.correction");
    return builder.CreateXor(normal, correction, "pyobf.junk.transition");
}
}
