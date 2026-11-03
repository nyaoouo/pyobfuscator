#include "bindings.hpp"
#include "metadata.hpp"

#include "../cff/cff.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

namespace pyobfuscator::native::archive {
namespace {

std::uint64_t literal(const llvm::Value *value) {
    const auto *integer = llvm::dyn_cast<llvm::ConstantInt>(value);
    if (integer == nullptr || integer->getBitWidth() > 64) invalid_binding("wrapper protocol argument is not a bounded literal");
    return integer->getZExtValue();
}

}  // namespace

WrapperView verify_wrapper(llvm::Module &module, const RecordBinding &record, const Bindings &bindings) {
    auto *wrapper = module.getFunction(record.wrapper);
    const auto markers = cff::collect_marked_functions(module);
    if (wrapper == nullptr || wrapper->isDeclaration() || wrapper->size() != 1 || wrapper->isVarArg() ||
        wrapper->arg_size() != 3 || !wrapper->getReturnType()->isVoidTy() ||
        !wrapper->getArg(0)->getType()->isPointerTy() || !wrapper->getArg(1)->getType()->isPointerTy() ||
        wrapper->getArg(2)->getType() != module.getDataLayout().getIntPtrType(module.getContext()) ||
        markers.find(record.wrapper) == markers.end() || markers.at(record.wrapper) != "pyobf.native.sdk")
        invalid_binding("missing or incompatible generated wrapper");
    llvm::SmallVector<llvm::AllocaInst *, 8> slots;
    for (auto &instruction : wrapper->getEntryBlock())
        if (auto *slot = llvm::dyn_cast<llvm::AllocaInst>(&instruction)) {
            if (!llvm::isAllocaPromotable(slot)) invalid_binding("wrapper has escaping parameter storage");
            slots.push_back(slot);
        }
    llvm::DominatorTree tree(*wrapper);
    llvm::PromoteMemToReg(slots, tree);
    llvm::CallInst *require = nullptr;
    for (auto &instruction : wrapper->getEntryBlock()) {
        if (llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) continue;
        if (const auto *ret = llvm::dyn_cast<llvm::ReturnInst>(&instruction)) {
            if (ret->getReturnValue() != nullptr) invalid_binding("wrapper returns a value");
        } else if (auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction)) {
            if (require != nullptr) invalid_binding("wrapper has extra calls");
            require = call;
        } else invalid_binding("wrapper has unexpected side effects or instructions");
    }
    const auto *callee = require == nullptr ? nullptr : require->getCalledFunction();
    if (callee == nullptr || callee->isDeclaration() || require->arg_size() != 7 ||
        !llvm::StringRef(llvm::demangle(callee->getName())).starts_with("pyobfuscator::native::archive::require_record(") ||
        markers.find(callee->getName().str()) == markers.end() ||
        markers.at(callee->getName().str()) != "pyobf.native.sdk") invalid_binding("wrapper does not call the linked require implementation");
    auto *pool = llvm::dyn_cast<llvm::GlobalVariable>(require->getArgOperand(0)->stripPointerCasts());
    auto *cache = llvm::dyn_cast<llvm::GlobalVariable>(require->getArgOperand(5)->stripPointerCasts());
    if (pool == nullptr || !pool->hasLocalLinkage() || !pool->isConstant() || !pool->hasInitializer() ||
        cache == nullptr || !cache->hasLocalLinkage() || cache->isConstant() || !cache->hasInitializer() ||
        !cache->getInitializer()->isNullValue() || require->getArgOperand(3) != wrapper->getArg(1) ||
        require->getArgOperand(4) != wrapper->getArg(2) || require->getArgOperand(6) != wrapper->getArg(0) ||
        literal(require->getArgOperand(2)) != record.index) invalid_binding("wrapper storage/cache/index/key ownership disagrees");
    const auto *data = llvm::dyn_cast<llvm::ConstantDataSequential>(pool->getInitializer());
    if (data == nullptr || !data->getElementType()->isIntegerTy(8)) invalid_binding("wrapper package is not static bytes");
    const auto bytes = data->getRawDataValues();
    if (bytes.size() < 40 || bytes.size() > 64 * 1024 * 1024 ||
        literal(require->getArgOperand(1)) != bytes.size()) invalid_binding("wrapper package size differs");
    for (const auto *user : cache->users())
        if (user != require) invalid_binding("record cache escapes its own generated wrapper");
    return {wrapper, pool, cache};
}

void verify_package(llvm::GlobalVariable &pool, const Bindings &bindings) {
    const auto bytes = llvm::cast<llvm::ConstantDataSequential>(pool.getInitializer())->getRawDataValues();
    const auto hash = llvm::SHA256::hash(llvm::ArrayRef<std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size()));
    if (llvm::toHex(hash, true) != bindings.package_hash || llvm::toHex(bytes.substr(16, 16), true) != bindings.archive_id)
        invalid_binding("linked package bytes differ from private bindings");
}

}  // namespace pyobfuscator::native::archive
