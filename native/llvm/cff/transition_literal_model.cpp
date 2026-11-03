#include "transition_model.hpp"
#include "scalar_mask.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

namespace pyobfuscator::native::cff {
TransitionModel::TransitionModel(const llvm::Function &owner, const llvm::ConstantInt &literal,
    std::uint32_t state, std::uint32_t seed) : mode_(Mode::literal) {
    if (!supported_scalar_integer(literal.getType())) { error_ = "literal model requires a supported scalar width"; return; }
    module_ = std::make_unique<llvm::Module>("literal-reference", owner.getContext());
    module_->setDataLayout(owner.getParent()->getDataLayout());
    auto &context = owner.getContext();
    auto *function = llvm::Function::Create(llvm::FunctionType::get(literal.getType(),
        {llvm::Type::getInt32Ty(context), llvm::PointerType::getUnqual(context)}, false),
        llvm::Function::ExternalLinkage, owner.getName(), *module_);
    auto *body = llvm::BasicBlock::Create(context, "entry", function);
    llvm::IRBuilder<> builder(body);
    result_ = emit_scalar_literal(builder, literal, function->getArg(1), state, seed);
    builder.CreateRet(const_cast<llvm::Value *>(result_)); model_ = function;
    if (llvm::verifyFunction(*function) || module_->size() != 1 || !module_->global_empty() ||
            !transition_literal_identity(*function, state, literal)) error_ = "literal model is not a pure entry-state constant";
}
}
