#pragma once

#include "call_frames.hpp"


#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {

struct Fixture {
    llvm::LLVMContext context;
    llvm::Module module{"frame-contract", context};
    llvm::Function *target, *owner, *helper;
    llvm::AllocaInst *frame;
    llvm::StoreInst *target_store, *argument_store, *result_store;
    llvm::LoadInst *target_load;
    llvm::CallInst *outer, *inner;
    llvm::MDNode *descriptor;
    FrameLayout layout;

    explicit Fixture(bool preparation = false, bool external = false) {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        auto *word = llvm::Type::getInt32Ty(context);
        auto *pointer = llvm::PointerType::getUnqual(context);
        auto *call_type = llvm::FunctionType::get(word, {word}, false);
        target = llvm::Function::Create(call_type, llvm::Function::ExternalLinkage, "target", module);
        llvm::IRBuilder<> builder(context);
        if (!external) {
            builder.SetInsertPoint(llvm::BasicBlock::Create(context, "entry", target));
            builder.CreateRet(builder.CreateAdd(target->getArg(0), builder.getInt32(9)));
        }
        owner = llvm::Function::Create(call_type, llvm::Function::ExternalLinkage, "owner", module);
        helper = llvm::Function::Create(llvm::FunctionType::get(builder.getVoidTy(), {pointer}, false),
            llvm::Function::InternalLinkage, "helper", module);
        helper->addFnAttr("pyobf.cff.transformed");
        std::vector<llvm::Type *> fields{pointer, word, word};
        if (preparation) fields.push_back(llvm::ArrayType::get(builder.getInt8Ty(), 16));
        layout = {llvm::StructType::get(context, fields), 0, 2, {1}, preparation ? 3u : ~0u};
        descriptor = frame_metadata(helper, target, layout);
        helper->setMetadata("pyobf.frame.helper", descriptor);
        helper->setMetadata("pyobf.frame.abi", llvm::MDNode::get(context, {
            llvm::ConstantAsMetadata::get(builder.getInt32(0)), llvm::MDString::get(context, ""),
            llvm::MDString::get(context, ""), llvm::MDString::get(context, "")}));
        builder.SetInsertPoint(llvm::BasicBlock::Create(context, "entry", helper));
        target_load = builder.CreateLoad(pointer, builder.CreateStructGEP(layout.type, helper->getArg(0), 0));
        auto *argument = builder.CreateLoad(word, builder.CreateStructGEP(layout.type, helper->getArg(0), 1));
        inner = builder.CreateCall(call_type, target_load, {argument});
        inner->setMetadata("pyobf.frame.inner", descriptor);
        result_store = builder.CreateStore(inner, builder.CreateStructGEP(layout.type, helper->getArg(0), 2));
        result_store->setMetadata("pyobf.frame.return-store", descriptor);
        builder.CreateRetVoid();
        builder.SetInsertPoint(llvm::BasicBlock::Create(context, "entry", owner));
        frame = builder.CreateAlloca(layout.type);
        frame->setMetadata("pyobf.frame.storage", descriptor);
        target_store = builder.CreateStore(target, builder.CreateStructGEP(layout.type, frame, 0));
        target_store->setMetadata("pyobf.frame.target", descriptor);
        argument_store = builder.CreateStore(owner->getArg(0), builder.CreateStructGEP(layout.type, frame, 1));
        argument_store->setMetadata("pyobf.frame.argument", llvm::MDNode::get(context,
            {descriptor, llvm::ConstantAsMetadata::get(builder.getInt32(0))}));
        outer = builder.CreateCall(helper, {frame});
        outer->setMetadata("pyobf.frame.invoke", descriptor);
        auto *result = builder.CreateLoad(word, builder.CreateStructGEP(layout.type, frame, 2));
        result->setMetadata("pyobf.frame.result", descriptor);
        builder.CreateRet(result);
        module.getOrInsertNamedMetadata("pyobf.frame.inventory")->addOperand(llvm::MDNode::get(context,
            {descriptor, llvm::ValueAsMetadata::get(owner), llvm::MDString::get(context, "original.call-frames.0")}));
    }
};

}  // namespace pyobfuscator::native::cff::test
