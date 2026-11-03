#pragma once

#include <string>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::archive {

[[noreturn]] inline void invalid_binding(const char *message) {
    llvm::report_fatal_error(llvm::StringRef(std::string("native archive binding: ") + message));
}

inline std::string text_field(const llvm::MDNode *node, unsigned index) {
    const auto *value = node != nullptr && index < node->getNumOperands() ?
        llvm::dyn_cast<llvm::MDString>(node->getOperand(index)) : nullptr;
    if (value == nullptr) invalid_binding("invalid metadata text field");
    return value->getString().str();
}

inline std::uint64_t number_field(const llvm::MDNode *node, unsigned index) {
    const auto *value = node != nullptr && index < node->getNumOperands() ?
        llvm::mdconst::dyn_extract<llvm::ConstantInt>(node->getOperand(index)) : nullptr;
    if (value == nullptr || value->getBitWidth() > 64) invalid_binding("invalid metadata integer field");
    return value->getZExtValue();
}

inline llvm::Value *value_field(const llvm::MDNode *node, unsigned index) {
    const auto *value = node != nullptr && index < node->getNumOperands() ?
        llvm::dyn_cast<llvm::ValueAsMetadata>(node->getOperand(index)) : nullptr;
    if (value == nullptr) invalid_binding("invalid metadata value field");
    return value->getValue();
}

inline std::string acquisition_id(const llvm::MDNode *node) {
    return text_field(node, 0) + ":" + text_field(node, 1);
}

}  // namespace pyobfuscator::native::archive
