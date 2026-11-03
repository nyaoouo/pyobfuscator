#pragma once

#include "call_frames.hpp"
#include "frame_profile.hpp"

#include <memory>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff::test {

enum class Profile { none, vp, count, edges, expected_count, expected_edges, wide_vp };

struct ProfileFixture {
    llvm::LLVMContext context;
    llvm::Module module{"frame-profile", context};
    llvm::Function *owner, *target, *helper;
    llvm::CallBase *source, *outer;
    llvm::CallInst *inner;
    llvm::MDNode *profile, *descriptor;
    std::unique_ptr<FrameProfileSeal> seal;
    std::map<std::string, GeneratedDefinition> generated;

    ProfileFixture(Profile kind = Profile::vp, bool invoke = true, bool external = true) {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        llvm::IRBuilder<> builder(context);
        auto *type = llvm::FunctionType::get(builder.getVoidTy(), false);
        target = llvm::Function::Create(type, llvm::Function::ExternalLinkage, "target", module);
        if (!external) llvm::IRBuilder<>(llvm::BasicBlock::Create(context, "entry", target)).CreateRetVoid();
        owner = llvm::Function::Create(type, llvm::Function::ExternalLinkage, "owner", module);
        auto *entry = llvm::BasicBlock::Create(context, "entry", owner);
        builder.SetInsertPoint(entry);
        if (invoke) {
            auto *personality = llvm::Function::Create(llvm::FunctionType::get(builder.getInt32Ty(), true),
                llvm::Function::ExternalLinkage, "__gxx_personality_seh0", module);
            owner->setPersonalityFn(personality);
            auto *normal = llvm::BasicBlock::Create(context, "normal", owner);
            auto *pad = llvm::BasicBlock::Create(context, "pad", owner);
            source = builder.CreateInvoke(target, normal, pad, {});
            builder.SetInsertPoint(normal); builder.CreateRetVoid();
            builder.SetInsertPoint(pad);
            auto *exception = builder.CreateLandingPad(llvm::StructType::get(context, {builder.getPtrTy(), builder.getInt32Ty()}), 0);
            exception->setCleanup(true); builder.CreateResume(exception);
        } else { source = builder.CreateCall(target); builder.CreateRetVoid(); }
        const auto number = [&](unsigned value) { return llvm::ConstantAsMetadata::get(builder.getInt32(value)); };
        profile = nullptr;
        if (kind == Profile::vp || kind == Profile::wide_vp)
            profile = llvm::MDNode::getDistinct(context, {llvm::MDString::get(context, "VP"),
                number(0), llvm::ConstantAsMetadata::get(builder.getInt64(kind == Profile::vp ? 100 : ~0ull)),
                llvm::ConstantAsMetadata::get(builder.getInt64(kind == Profile::vp ? 123456 : 0xfedcba9876543210ull)),
                llvm::ConstantAsMetadata::get(builder.getInt64(99))});
        else if (kind != Profile::none) {
            std::vector<llvm::Metadata *> operands{llvm::MDString::get(context, "branch_weights")};
            if (kind == Profile::expected_count || kind == Profile::expected_edges)
                operands.push_back(llvm::MDString::get(context, "expected"));
            operands.push_back(number(999));
            if (kind == Profile::edges || kind == Profile::expected_edges) operands.push_back(number(1));
            profile = llvm::MDNode::getDistinct(context, operands);
        }
        source->setMetadata(llvm::LLVMContext::MD_prof, profile);
        seal = std::make_unique<FrameProfileSeal>(module);
        helper = llvm::Function::Create(llvm::FunctionType::get(builder.getVoidTy(), {builder.getPtrTy()}, false),
            llvm::Function::InternalLinkage, "helper", module);
        FrameLayout layout{llvm::StructType::get(context, {builder.getPtrTy()}, false), 0, ~0u, {}};
        descriptor = frame_metadata(helper, target, layout);
        helper->setMetadata("pyobf.frame.helper", descriptor);
        builder.SetInsertPoint(llvm::BasicBlock::Create(context, "entry", helper));
        auto *callee = builder.CreateLoad(builder.getPtrTy(), builder.CreateStructGEP(layout.type, helper->getArg(0), 0));
        inner = builder.CreateCall(type, callee, {});
        inner->setMetadata("pyobf.frame.inner", descriptor);
        inner->setMetadata(llvm::LLVMContext::MD_prof, frame_profiles(*source).inner);
        builder.CreateRetVoid();
        source->setMetadata("pyobf.frame.plan", descriptor);
        generated.emplace("helper", GeneratedDefinition{helper, "owner", "original.site.0",
            external ? "external-calls" : "call-frames", {}});
    }

    void release() {
        llvm::IRBuilder<> builder(source);
        auto *frame = builder.CreateAlloca(llvm::StructType::get(context, {builder.getPtrTy()}, false));
        builder.CreateStore(target, builder.CreateStructGEP(frame->getAllocatedType(), frame, 0));
        if (const auto *invoke = llvm::dyn_cast<llvm::InvokeInst>(source))
            outer = builder.CreateInvoke(helper, invoke->getNormalDest(), invoke->getUnwindDest(), {frame});
        else outer = builder.CreateCall(helper, {frame});
        outer->setMetadata("pyobf.frame.invoke", descriptor);
        outer->setMetadata(llvm::LLVMContext::MD_prof, frame_profiles(*source).outer);
        source->eraseFromParent(); source = nullptr;
    }
};

}  // namespace pyobfuscator::native::cff::test
