#pragma once

#include "hybrid_flow_fixture.hpp"
#include "hybrid_scalar_bindings.hpp"
#include "scalar_mask.hpp"
#include "transition_layers.hpp"

namespace pyobfuscator::native::cff::test {
struct HybridScalarFixture : HybridFixture {
    llvm::ReturnInst *ret;
    const llvm::ConstantInt *literal;
    llvm::Value *decoded;
    std::unique_ptr<TransitionLayers> layers;
    std::unique_ptr<HybridScalarBindings> binding;
    HybridScalarFixture(unsigned width = 33, unsigned seed = 17) : HybridFixture(seed, std::nullopt, width) {
        ret = llvm::cast<llvm::ReturnInst>(returned->getTerminator());
        literal = llvm::cast<llvm::ConstantInt>(ret->getReturnValue());
        layers = std::make_unique<TransitionLayers>(*owner, state, layout.transition_salt, TransitionLayerPlans{});
        binding = std::make_unique<HybridScalarBindings>(*owner, layout, state, *layers, 0x12345678u);
        llvm::IRBuilder<> builder(ret);
        decoded = emit_scalar_literal(builder, *literal, state, layout.states[returned], 0x12345678u);
        ret->setOperand(0, decoded);
    }
    std::string verify() const { return seal->verify(*owner, binding.get()); }
    bool owns() const { return binding->preserves_terminal_operand(*ret, 0, literal, ret->getReturnValue()); }
};
}
