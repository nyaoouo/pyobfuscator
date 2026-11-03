#include "frame_fixture.hpp"

#include <functional>

using namespace pyobfuscator::native::cff;
using pyobfuscator::native::cff::test::Fixture;

int main() {
    Fixture valid;
    if (llvm::verifyModule(valid.module) || !verify_call_frames(valid.module).empty()) return 1;
    const std::function<void(Fixture &)> mutations[]{
        [](Fixture &f) { f.target_store->setOperand(0, f.owner); },
        [](Fixture &f) { f.argument_store->setOperand(1, f.target_store->getPointerOperand()); },
        [](Fixture &f) { f.argument_store->setMetadata("pyobf.frame.argument", nullptr); },
        [](Fixture &f) { f.frame->setMetadata("pyobf.frame.storage", nullptr); },
        [](Fixture &f) { f.outer->setMetadata("pyobf.frame.invoke", nullptr); },
        [](Fixture &f) { f.outer->setCallingConv(llvm::CallingConv::Fast); },
        [](Fixture &f) { f.inner->setCallingConv(llvm::CallingConv::Fast); },
        [](Fixture &f) { f.inner->addFnAttr(llvm::Attribute::NoUnwind); },
        [](Fixture &f) { f.helper->removeFnAttr("pyobf.cff.transformed"); },
        [](Fixture &f) { f.helper->setLinkage(llvm::Function::ExternalLinkage); },
        [](Fixture &f) { f.result_store->setMetadata("pyobf.frame.return-store", nullptr); },
        [](Fixture &f) { f.target_load->setOperand(0, f.inner->getArgOperand(0)); },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.outer);
            builder.CreateStore(builder.getInt32(1), f.argument_store->getPointerOperand());
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.outer);
            auto *other = builder.CreateAlloca(f.layout.type);
            f.outer->setArgOperand(0, other);
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.outer);
            auto *escape = builder.CreateAlloca(builder.getPtrTy());
            builder.CreateStore(f.frame, escape);
        },
        [](Fixture &f) { f.module.eraseNamedMetadata(f.module.getNamedMetadata("pyobf.frame.inventory")); },
        [](Fixture &f) {
            auto *inventory = f.module.getNamedMetadata("pyobf.frame.inventory");
            inventory->addOperand(inventory->getOperand(0));
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.outer);
            auto *duplicate = builder.CreateCall(f.helper, {f.frame});
            duplicate->setMetadata("pyobf.frame.invoke", f.descriptor);
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.inner);
            auto *leak = new llvm::GlobalVariable(f.module, builder.getPtrTy(), false,
                llvm::GlobalValue::PrivateLinkage, llvm::ConstantPointerNull::get(builder.getPtrTy()), "leaked_frame");
            builder.CreateStore(f.helper->getArg(0), leak);
        }
    };
    for (const bool external : {false, true}) {
        Fixture baseline(false, external);
        if (llvm::verifyModule(baseline.module) || !verify_call_frames(baseline.module).empty()) return 2;
        for (unsigned index = 0; index < std::size(mutations); ++index) {
            Fixture fixture(false, external);
            mutations[index](fixture);
            if (verify_call_frames(fixture.module).empty()) {
                llvm::errs() << "frame mutation unexpectedly accepted: " << index << '\n';
                return 10 + index;
            }
        }
    }
    Fixture imported(false, true), prepared_import(true, true);
    if (!read_frame_metadata(imported.descriptor)->external || !read_frame_metadata(prepared_import.descriptor)->external ||
        llvm::verifyModule(prepared_import.module) || !verify_call_frames(prepared_import.module).empty()) return 41;
    imported.target->setLinkage(llvm::Function::ExternalWeakLinkage);
    if (verify_call_frames(imported.module).empty()) return 42;
    Fixture lost_profile(false, true);
    lost_profile.descriptor->replaceOperandWith(lost_profile.descriptor->getNumOperands() - 1,
        llvm::MDString::get(lost_profile.context, "unknown-profile"));
    if (verify_call_frames(lost_profile.module).empty()) return 43;
    Fixture became_definition(false, true);
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(became_definition.context, "entry", became_definition.target));
    builder.CreateRet(builder.getInt32(1));
    if (verify_call_frames(became_definition.module).empty()) return 44;
    Fixture changed_control(false, true);
    changed_control.target->addFnAttr(llvm::Attribute::ReturnsTwice);
    if (verify_call_frames(changed_control.module).empty()) return 45;
    finish_call_frames(valid.module);
    return llvm::verifyModule(valid.module) || !verify_call_frames(valid.module).empty() ? 40 : 0;
}
