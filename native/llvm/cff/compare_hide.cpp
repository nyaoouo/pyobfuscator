#include "recipe.hpp"

#include "compare_codec.hpp"
#include "site_provenance.hpp"
#include "site_report.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {

int constant_side(const llvm::ICmpInst &comparison) {
    if (!comparison.isEquality()) return -1;
    const bool left = llvm::isa<llvm::Constant>(comparison.getOperand(0));
    const bool right = llvm::isa<llvm::Constant>(comparison.getOperand(1));
    return left == right ? -1 : left ? 0 : 1;
}

bool eligible(const llvm::ICmpInst &comparison, unsigned side) {
    const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(comparison.getOperand(side));
    return constant != nullptr && supported_scalar_integer(constant->getType()) &&
           constant->getBitWidth() >= 2;
}

}  // namespace

unsigned comparison_identity_operand(const llvm::Instruction &, unsigned) {
    // Ordinary optimization can swap constant sides or invert eq/ne without losing the use.
    return 0;
}

std::vector<InstructionSite> discover_comparison_sites(llvm::Function &function, const ResolvedRecipe &) {
    std::vector<InstructionSite> sites;
    for (auto &block : function) for (auto &instruction : block) {
        auto *comparison = llvm::dyn_cast<llvm::ICmpInst>(&instruction);
        if (comparison == nullptr) continue;
        const auto side = constant_side(*comparison);
        if (side >= 0) sites.push_back({comparison, static_cast<unsigned>(side),
            eligible(*comparison, side) ? std::string{} : "comparison hiding supports scalar i2 through i128 literals"});
    }
    return sites;
}

unsigned hide_comparison_constants(llvm::BasicBlock &body, llvm::Value *state_slot,
                                    std::uint32_t expected_state, std::uint32_t salt,
                                    SiteCoverage *coverage) {
    unsigned hidden = 0;
    for (auto iterator = body.begin(); iterator != body.end();) {
        auto *comparison = llvm::dyn_cast<llvm::ICmpInst>(&*iterator++);
        if (comparison == nullptr) continue;
        const auto side = constant_side(*comparison);
        if (side < 0 || !eligible(*comparison, side)) continue;
        auto *constant = llvm::cast<llvm::ConstantInt>(comparison->getOperand(side));
        auto *type = constant->getType();
        const auto width = constant->getBitWidth();
        const auto site_salt = component_seed(salt, body.getParent()->getName(),
                                              instruction_provenance(*comparison));
        const auto codec = make_compare_codec(width, site_salt);
        const auto expected_key = scalar_mask_value(width, expected_state, site_salt, ScalarMaskDomain::comparison);
        const auto encoded = encode_comparison(constant->getValue(), expected_key, codec);
        llvm::IRBuilder<> builder(comparison);
        auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.compare.state");
        auto *key = emit_scalar_mask(builder, type, state, site_salt, ScalarMaskDomain::comparison);
        auto *value = emit_comparison(builder, comparison->getOperand(1 - side), key, codec);
        // The new bijection preserves equality, not original same-sign assumptions.
        // Preserve condition identity for the independently frozen normal-flow plan.
        comparison->setSameSign(false);
        comparison->setName("pyobf.compare.hidden");
        if (coverage != nullptr) {
            if (side == 0) coverage->relocate_use("integer-literals", *comparison, 0, *comparison, 1);
            coverage->applied("comparison-constants", *comparison, side);
            coverage->record_type("comparison-constants", "i" + std::to_string(width));
        }
        comparison->setOperand(0, value);
        comparison->setOperand(1, llvm::ConstantInt::get(type, encoded));
        ++hidden;
    }
    return hidden;
}

}  // namespace pyobfuscator::native::cff
