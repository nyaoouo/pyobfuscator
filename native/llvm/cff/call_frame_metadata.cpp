#include "call_frames.hpp"

#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Constants.h"

namespace pyobfuscator::native::cff {

std::optional<unsigned> frame_number(const llvm::MDNode *node, unsigned index) {
    const auto *value = node == nullptr || index >= node->getNumOperands() ? nullptr :
        llvm::mdconst::dyn_extract<llvm::ConstantInt>(node->getOperand(index));
    if (value == nullptr || !value->getType()->isIntegerTy(32)) return {};
    return static_cast<unsigned>(value->getZExtValue());
}

llvm::MDNode *frame_metadata(llvm::Function *helper, llvm::Function *target, const FrameLayout &layout) {
    auto &context = helper->getContext();
    const auto number = [&](unsigned value) { return llvm::ConstantAsMetadata::get(
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), value)); };
    std::vector<llvm::Metadata *> fields{llvm::ValueAsMetadata::get(helper), llvm::ValueAsMetadata::get(target),
        llvm::ConstantAsMetadata::get(llvm::UndefValue::get(layout.type)), number(layout.target), number(layout.result)};
    for (const auto index : layout.arguments) fields.push_back(number(index));
    if (layout.padding != ~0u) fields.push_back(number(layout.padding));
    if (target->isDeclaration()) fields.push_back(llvm::MDString::get(context, "external-calls"));
    return llvm::MDNode::get(context, fields);
}

std::optional<FrameInfo> read_frame_metadata(const llvm::MDNode *node) {
    if (node == nullptr || node->getNumOperands() < 5) return {};
    const auto function = [&](unsigned index) {
        const auto *value = llvm::dyn_cast<llvm::ValueAsMetadata>(node->getOperand(index));
        return value == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(value->getValue());
    };
    auto *helper = function(0), *target = function(1);
    const auto *value = llvm::dyn_cast<llvm::ConstantAsMetadata>(node->getOperand(2));
    auto *type = value == nullptr ? nullptr : llvm::dyn_cast<llvm::StructType>(value->getValue()->getType());
    const auto target_index = frame_number(node, 3), result_index = frame_number(node, 4);
    const auto *profile = llvm::dyn_cast<llvm::MDString>(node->getOperand(node->getNumOperands() - 1));
    const bool external = profile != nullptr && profile->getString() == "external-calls";
    const auto operands = node->getNumOperands() - external;
    if (helper == nullptr || target == nullptr || target->isDeclaration() != external || target->isIntrinsic() ||
        (external && (!target->hasExternalLinkage() || target->isVarArg() ||
            target->hasFnAttribute(llvm::Attribute::ReturnsTwice) || target->hasFnAttribute(llvm::Attribute::Convergent) ||
            target->hasFnAttribute(llvm::Attribute::NoDuplicate) || target->hasFnAttribute(llvm::Attribute::NoMerge))) ||
        target->hasAvailableExternallyLinkage() || target->getAddressSpace() != 0 ||
        type == nullptr || !llvm::isa<llvm::UndefValue>(value->getValue()) ||
        !target_index || !result_index || (operands != target->arg_size() + 5 &&
                                         operands != target->arg_size() + 6) ||
        *target_index >= type->getNumElements() || !type->getElementType(*target_index)->isPointerTy() ||
        type->getElementType(*target_index)->getPointerAddressSpace() != 0) return {};
    FrameInfo info{helper, target, {type, *target_index, *result_index, {}}, external};
    std::set<unsigned> indices{*target_index};
    for (unsigned index = 0; index < target->arg_size(); ++index) {
        const auto field = frame_number(node, index + 5);
        if (!field || *field >= type->getNumElements() || !indices.insert(*field).second ||
            type->getElementType(*field) != target->getArg(index)->getType()) return {};
        info.layout.arguments.push_back(*field);
    }
    if (target->getReturnType()->isVoidTy()) { if (*result_index != ~0u) return {}; }
    else if (*result_index >= type->getNumElements() || !indices.insert(*result_index).second ||
             type->getElementType(*result_index) != target->getReturnType()) return {};
    if (operands == target->arg_size() + 6) {
        const auto padding = frame_number(node, target->arg_size() + 5);
        const auto *array = !padding || *padding >= type->getNumElements() ? nullptr :
            llvm::dyn_cast<llvm::ArrayType>(type->getElementType(*padding));
        if (array == nullptr || !array->getElementType()->isIntegerTy(8) || array->getNumElements() == 0 ||
            array->getNumElements() > 2097152 || !indices.insert(*padding).second) return {};
        info.layout.padding = *padding;
    }
    if (indices.size() != type->getNumElements()) return {};
    return info;
}

}  // namespace pyobfuscator::native::cff
