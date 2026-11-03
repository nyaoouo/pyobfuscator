#include "transition_layers.hpp"
#include "transition_registry.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {
namespace {
std::optional<std::uint32_t> word(const llvm::MDNode *node, unsigned index) {
    if (node == nullptr || index >= node->getNumOperands()) return {};
    const auto *value = llvm::mdconst::dyn_extract<llvm::ConstantInt>(node->getOperand(index));
    if (value == nullptr || !value->getType()->isIntegerTy(32)) return {};
    return value->getZExtValue();
}
}
std::optional<TransitionLayerDescription> read_transition_layers(const llvm::MDNode *node) {
    if (node == nullptr || node->getNumOperands() != 5 || word(node, 0) != 1) return {};
    const auto state = word(node, 1), salt = word(node, 2);
    const auto *provenance = llvm::dyn_cast_or_null<llvm::MDString>(node->getOperand(3));
    const auto *models = llvm::dyn_cast_or_null<llvm::MDNode>(node->getOperand(4));
    if (!state || !salt || provenance == nullptr || provenance->getString().size() > 4096 || models == nullptr ||
            models->getNumOperands() == 0 || models->getNumOperands() > registered_transition_models().size()) return {};
    TransitionLayerDescription result{*state, *salt, provenance->getString().str(), {}};
    std::set<const TransitionModelRegistration *> seen;
    for (const auto &entry : models->operands()) {
        const auto *fields = llvm::dyn_cast_or_null<llvm::MDNode>(entry);
        if (fields == nullptr || fields->getNumOperands() != 3) return {};
        const auto *name = llvm::dyn_cast_or_null<llvm::MDString>(fields->getOperand(0));
        const auto seed = word(fields, 1), rounds = word(fields, 2);
        const auto *model = name == nullptr ? nullptr : find_transition_model(name->getString());
        if (model == nullptr || !seed || !rounds || !seen.insert(model).second ||
                (name->getString() == "reachable-junk" ? *rounds < 1 || *rounds > 8 : *rounds != 0)) return {};
        result.models.push_back({model, *seed, *rounds});
    }
    return result;
}
llvm::MDNode *describe_transition_layers(llvm::LLVMContext &context, const TransitionLayerDescription &description) {
    const auto number = [&](std::uint32_t value) { return llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), value)); };
    llvm::SmallVector<llvm::Metadata *, 4> models;
    for (const auto &spec : description.models) models.push_back(llvm::MDNode::get(context,
        {llvm::MDString::get(context, spec.model->name), number(spec.seed), number(spec.rounds)}));
    return llvm::MDNode::get(context, {number(1), number(description.state), number(description.salt),
        llvm::MDString::get(context, description.provenance), llvm::MDNode::get(context, models)});
}
bool has_transition_layers(const llvm::Function &function) {
    for (const auto &body : function) for (const auto &instruction : body)
        if (instruction.getMetadata("pyobf.transition.layers")) return true;
    return false;
}
}
