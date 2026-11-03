#include "indexed_locals.hpp"
#include "call_frames.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

llvm::MDNode *local_descriptor(llvm::AllocaInst &storage, unsigned slot, unsigned routes, unsigned controls) {
    llvm::IRBuilder<> builder(storage.getContext());
    return llvm::MDNode::get(storage.getContext(), {
        llvm::ConstantAsMetadata::get(builder.getInt32(slot)),
        llvm::ConstantAsMetadata::get(builder.getInt64(llvm::cast<llvm::ConstantInt>(storage.getArraySize())->getZExtValue())),
        llvm::ConstantAsMetadata::get(builder.getInt64(storage.getAlign().value())),
        llvm::ConstantAsMetadata::get(llvm::UndefValue::get(storage.getAllocatedType())),
        llvm::MDString::get(storage.getContext(), instruction_provenance(storage)),
        llvm::ConstantAsMetadata::get(builder.getInt32(routes)), llvm::ConstantAsMetadata::get(builder.getInt32(controls))});
}

std::optional<LocalInfo> local_info(const llvm::MDNode *descriptor) {
    if (descriptor == nullptr || descriptor->getNumOperands() != 7) return {};
    const auto slot = frame_number(descriptor, 0), routes = frame_number(descriptor, 5), controls = frame_number(descriptor, 6);
    const auto *count = llvm::mdconst::dyn_extract<llvm::ConstantInt>(descriptor->getOperand(1));
    const auto *alignment = llvm::mdconst::dyn_extract<llvm::ConstantInt>(descriptor->getOperand(2));
    const auto *type = llvm::dyn_cast<llvm::ConstantAsMetadata>(descriptor->getOperand(3));
    const auto *site = llvm::dyn_cast<llvm::MDString>(descriptor->getOperand(4));
    if (!slot || !routes || !*routes || !controls || count == nullptr || !count->getType()->isIntegerTy(64) ||
        count->isZero() || alignment == nullptr || !alignment->getType()->isIntegerTy(64) ||
        !alignment->getValue().isPowerOf2() || type == nullptr || !llvm::isa<llvm::UndefValue>(type->getValue()) ||
        site == nullptr || site->getString().empty()) return {};
    return LocalInfo{*slot, count->getZExtValue(), alignment->getZExtValue(), type->getValue()->getType(), site->getString().str(), *routes, *controls};
}

}  // namespace pyobfuscator::native::cff
