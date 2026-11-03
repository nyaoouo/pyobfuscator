#include "cff.hpp"
#include "transition_encode.hpp"
#include "recipe.hpp"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_decoy_sites(llvm::Function &function, const ResolvedRecipe &) {
    std::vector<InstructionSite> sites;
    for (auto &block : function) {
        auto *term = block.getTerminator();
        if (llvm::isa<llvm::BranchInst, llvm::SwitchInst>(term)) sites.push_back({term, 0, {}});
    }
    return sites;
}

llvm::Value *select_decoy_transition(llvm::IRBuilder<> &builder, llvm::Value *normal,
                                     llvm::Value *state_slot,
                                     std::uint32_t expected_state, std::uint32_t salt,
                                     const ResolvedRecipe &) {
    // Valid execution reaches this body at expected_state. A lower, non-equal
    // range check leaves a retained alternate edge for corrupted state flow.
    auto *probe = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.decoy.state");
    probe->setVolatile(true);
    auto *guard = builder.CreateICmpULT(probe, builder.getInt32(expected_state >> 1),
                                        "pyobf.decoy.guard");
    const auto alternate = encode_delta(expected_state, expected_state - 1, salt);
    // Keep the wrong-state arm distinct from opaque selections and junk coefficients.
    const auto coefficient = ((salt ^ 0xa53c91ebu) & ~0x10u) | 0xa5a5a5a5u;
    auto *product = builder.CreateMul(probe, builder.getInt32(coefficient), "pyobf.decoy.product");
    llvm::cast<llvm::Instruction>(product)->setMetadata("pyobf.cff.public-coefficient", llvm::MDNode::get(builder.getContext(), {}));
    auto *fake = builder.CreateXor(product, builder.getInt32(alternate ^ (expected_state * coefficient)), "pyobf.decoy.alternate");
    return builder.CreateSelect(guard, fake, normal,
                                "pyobf.decoy.pick");
}

}  // namespace pyobfuscator::native::cff
