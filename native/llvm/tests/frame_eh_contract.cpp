#include "call_frames.hpp"
#include "exceptional_origins.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace pyobfuscator::native::cff;

struct Fixture {
    llvm::LLVMContext context;
    llvm::Module module{"eh-completion", context};
    llvm::Function *owner;
    llvm::BasicBlock *entry, *normal, *pad;
    llvm::LoadInst *result;

    Fixture() {
        auto *type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
        auto *target = llvm::Function::Create(type, llvm::Function::ExternalLinkage, "target", module);
        owner = llvm::Function::Create(type, llvm::Function::ExternalLinkage, "owner", module);
        auto *personality = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getInt32Ty(context), true),
            llvm::Function::ExternalLinkage, "__gxx_personality_seh0", module);
        owner->setPersonalityFn(personality);
        entry = llvm::BasicBlock::Create(context, "entry", owner);
        normal = llvm::BasicBlock::Create(context, "normal", owner);
        pad = llvm::BasicBlock::Create(context, "pad", owner);
        llvm::IRBuilder<> builder(entry);
        auto *storage = builder.CreateAlloca(builder.getInt32Ty());
        auto *descriptor = llvm::MDNode::get(context, {});
        auto *invoke = builder.CreateInvoke(target, normal, pad, {});
        invoke->setMetadata("pyobf.frame.invoke", descriptor);
        builder.SetInsertPoint(normal);
        result = builder.CreateLoad(builder.getInt32Ty(), storage);
        result->setMetadata("pyobf.frame.result", descriptor);
        builder.CreateRetVoid();
        builder.SetInsertPoint(pad);
        auto *exception = builder.CreateLandingPad(llvm::StructType::get(context, {builder.getPtrTy(), builder.getInt32Ty()}), 0);
        exception->setCleanup(true);
        exception->addClause(llvm::ConstantPointerNull::get(builder.getPtrTy()));
        builder.CreateResume(exception);
    }
};

int main() {
    Fixture baseline;
    if (llvm::verifyModule(baseline.module, &llvm::errs()) || !validate_frame_completion(*baseline.owner).empty()) return 1;
    for (unsigned mutation = 0; mutation < 3; ++mutation) {
        Fixture fixture;
        if (mutation == 0) fixture.result->moveBefore(fixture.entry->getTerminator()->getIterator());
        else if (mutation == 1) fixture.result->moveBefore(fixture.pad->getTerminator()->getIterator());
        else {
            auto *join = llvm::BasicBlock::Create(fixture.context, "join", fixture.owner);
            llvm::IRBuilder<> builder(join);
            builder.CreateRetVoid();
            for (auto *block : {fixture.normal, fixture.pad}) {
                block->getTerminator()->eraseFromParent();
                llvm::IRBuilder<>(block).CreateBr(join);
            }
            fixture.result->moveBefore(join->getTerminator()->getIterator());
        }
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || validate_frame_completion(*fixture.owner).empty()) {
            llvm::errs() << "unsafe result completion accepted at mutation " << mutation << "\n";
            return 1;
        }
    }
    for (unsigned mutation = 0; mutation < 4; ++mutation) {
        Fixture fixture;
        auto *pad = llvm::cast<llvm::LandingPadInst>(&fixture.pad->front());
        llvm::BasicBlock *alternate = nullptr;
        if (mutation == 3) {
            alternate = llvm::BasicBlock::Create(fixture.context, "alternate", fixture.owner);
            llvm::IRBuilder<> builder(alternate);
            auto *exception = builder.CreateLandingPad(pad->getType(), 0);
            exception->setCleanup(true);
            builder.CreateResume(exception);
        }
        ExceptionalOrigins origins(*fixture.owner);
        if (!origins.check(*fixture.owner).empty()) return 1;
        if (mutation == 0) pad->setCleanup(false);
        else if (mutation == 1) fixture.owner->setPersonalityFn(llvm::Function::Create(
            llvm::FunctionType::get(llvm::Type::getInt32Ty(fixture.context), true),
            llvm::Function::ExternalLinkage, "other_personality", fixture.module));
        else if (mutation == 2) pad->setOperand(0, new llvm::GlobalVariable(fixture.module,
            llvm::Type::getInt8Ty(fixture.context), true, llvm::GlobalValue::ExternalLinkage,
            nullptr, "other_type"));
        else llvm::cast<llvm::InvokeInst>(fixture.entry->getTerminator())->setUnwindDest(alternate);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || origins.check(*fixture.owner).empty()) {
            llvm::errs() << "changed exception origin accepted at mutation " << mutation << "\n";
            return 1;
        }
    }
    for (bool transfer : {false, true}) {
        Fixture fixture;
        ExceptionalOrigins origins(*fixture.owner);
        auto *original = llvm::cast<llvm::InvokeInst>(fixture.entry->getTerminator());
        llvm::IRBuilder<> builder(original);
        auto *replacement = builder.CreateInvoke(original->getFunctionType(), original->getCalledOperand(),
            original->getNormalDest(), original->getUnwindDest(), {});
        if (transfer && !origins.replace(*original, *replacement).empty()) return 1;
        original->eraseFromParent();
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || origins.check(*fixture.owner).empty() != transfer)
            return 1;
    }
    return 0;
}
