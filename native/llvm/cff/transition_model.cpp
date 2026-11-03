#include "transition_model.hpp"
#include "recipe.hpp"
#include "transition_registry.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

namespace pyobfuscator::native::cff {
TransitionModel::TransitionModel(const llvm::Function &owner, const Component &component,
    llvm::StringRef provenance, std::uint32_t state, std::uint32_t seed, const ResolvedRecipe &recipe) {
    module_ = std::make_unique<llvm::Module>("transition-reference", owner.getContext());
    module_->setDataLayout(owner.getParent()->getDataLayout());
    auto &context = owner.getContext();
    auto *word = llvm::Type::getInt32Ty(context);
    auto *function = llvm::Function::Create(llvm::FunctionType::get(word, {word, llvm::PointerType::getUnqual(context)}, false),
        llvm::Function::ExternalLinkage, owner.getName(), *module_);
    auto *body = llvm::BasicBlock::Create(context, "entry", function);
    llvm::IRBuilder<> builder(body);
    auto *end = builder.CreateUnreachable();
    end->setMetadata("pyobf.cff.site", llvm::MDNode::get(context, llvm::MDString::get(context, provenance)));
    builder.SetInsertPoint(end);
    if (component.transition == nullptr || component.transition_model == nullptr ||
            component.transition_model->emit != component.transition || llvm::StringRef(component.transition_model->name) != component.name) {
        error_ = "transition component has no registered identity model"; return;
    }
    result_ = component.transition(builder, function->getArg(0), function->getArg(1), state, seed, recipe);
    if (result_ == nullptr || !result_->getType()->isIntegerTy(32) || !llvm::isa<llvm::Instruction>(result_)) {
        error_ = "transition model did not return an actual i32 runtime layer"; return;
    }
    builder.CreateRet(const_cast<llvm::Value *>(result_)); end->eraseFromParent(); model_ = function;
    if (llvm::verifyFunction(*function) || module_->size() != 1 || !module_->global_empty() ||
            !transition_model_identity(*function, state)) error_ = "transition model is not a pure entry-state identity";
}
TransitionModel::~TransitionModel() = default;
}
