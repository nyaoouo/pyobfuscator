#include "transition_model.hpp"
#include "opaque_expression.hpp"
#include "scalar_mask.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

namespace pyobfuscator::native::cff {
TransitionModel::TransitionModel(const llvm::Function &owner, std::uint32_t state, std::uint32_t salt,
    std::optional<std::uint32_t> literal_seed)
    : mode_(Mode::predicate) {
    module_ = std::make_unique<llvm::Module>("predicate-reference", owner.getContext());
    module_->setDataLayout(owner.getParent()->getDataLayout());
    auto &context = owner.getContext();
    auto *function = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getInt1Ty(context),
        {llvm::Type::getInt32Ty(context), llvm::PointerType::getUnqual(context)}, false),
        llvm::Function::ExternalLinkage, owner.getName(), *module_);
    auto *body = llvm::BasicBlock::Create(context, "entry", function);
    llvm::IRBuilder<> builder(body);
    result_ = emit_opaque_true(builder, function->getArg(1), salt, salt % 3);
    if (literal_seed) for (auto iterator = body->begin(); iterator != body->end();) {
        auto &instruction = *iterator++;
        if (!llvm::isa<llvm::BinaryOperator, llvm::ICmpInst>(instruction)) continue;
        for (unsigned index = 0; index != instruction.getNumOperands(); ++index)
            if (const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(index))) {
                llvm::IRBuilder<> decode(&instruction);
                instruction.setOperand(index, emit_scalar_literal(decode, *constant, function->getArg(1), state, *literal_seed));
            }
    }
    builder.CreateRet(const_cast<llvm::Value *>(result_)); model_ = function;
    if (llvm::verifyFunction(*function) || module_->size() != 1 || !module_->global_empty() ||
            !transition_predicate_identity(*function, state)) error_ = "predicate model is not a pure entry-state true value";
}
}
