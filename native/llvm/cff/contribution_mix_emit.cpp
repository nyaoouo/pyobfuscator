#include "contribution_mix.hpp"

#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
llvm::Value *emit_contribution_mix(llvm::IRBuilder<> &builder, const ContributionMixPlan &plan,
    llvm::ArrayRef<llvm::Value *> inputs) {
    if (inputs.size() != plan.inputs) llvm::report_fatal_error("contribution mix input count changed");
    for (const auto *input : inputs)
        if (input == nullptr || !input->getType()->isIntegerTy(32)) llvm::report_fatal_error("contribution mix requires i32 observations");
    std::vector<llvm::Value *> values;
    for (const auto &node : plan.nodes) {
        if (node.kind == ContributionMixPlan::Kind::literal) values.push_back(builder.getInt32(node.value));
        else if (node.kind == ContributionMixPlan::Kind::input) values.push_back(inputs[node.value]);
        else values.push_back(builder.CreateBinOp(static_cast<llvm::Instruction::BinaryOps>(node.opcode), values[node.left], values[node.right]));
    }
    return values[plan.root];
}
}
