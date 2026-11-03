#include "frame_profile_fixture.hpp"

#include "llvm/IR/Verifier.h"
#include "llvm/IR/ProfDataUtils.h"
#include "llvm/Support/raw_ostream.h"

using namespace pyobfuscator::native::cff;
using namespace pyobfuscator::native::cff::test;

int main() {
    for (bool invoke : {false, true}) for (bool external : {false, true})
        for (auto kind : {Profile::none, Profile::vp, Profile::count, Profile::edges,
                          Profile::expected_count, Profile::expected_edges, Profile::wide_vp}) {
            if (!invoke && (kind == Profile::edges || kind == Profile::expected_edges)) continue;
            ProfileFixture fixture(kind, invoke, external);
            const auto policy = frame_profiles(*fixture.source);
            const bool weights = kind == Profile::count || kind == Profile::expected_count ||
                kind == Profile::edges || kind == Profile::expected_edges;
            const bool inner = kind != Profile::none && kind != Profile::edges && kind != Profile::expected_edges;
            if (policy.outer != (weights ? fixture.profile : nullptr) || policy.inner != (inner ? fixture.profile : nullptr)) {
                llvm::errs() << "wrong profile policy for kind " << static_cast<unsigned>(kind)
                             << "; branch-weight API=" << llvm::isBranchWeightMD(fixture.profile) << "\n";
                return 1;
            }
            if (llvm::verifyModule(fixture.module, &llvm::errs()) || !fixture.seal->bind(fixture.module, fixture.generated).empty()) return 1;
            fixture.release();
            if (llvm::verifyModule(fixture.module, &llvm::errs()) || !fixture.seal->verify(fixture.module).empty()) return 1;
        }
    for (unsigned mutation = 0; mutation < 14; ++mutation) {
        const auto kind = mutation < 4 ? Profile::vp : mutation == 4 ? Profile::wide_vp :
            mutation == 5 ? Profile::edges : mutation < 8 ? Profile::count : Profile::none;
        ProfileFixture fixture(kind);
        if (const auto reason = fixture.seal->bind(fixture.module, fixture.generated); !reason.empty()) {
            llvm::errs() << "profile fixture binding failed: " << reason << "\n"; return 1;
        }
        fixture.release();
        llvm::IRBuilder<> builder(fixture.context);
        if (mutation == 0) fixture.inner->setMetadata(llvm::LLVMContext::MD_prof, nullptr);
        else if (mutation == 1) fixture.outer->setMetadata(llvm::LLVMContext::MD_prof, fixture.profile);
        else if (mutation == 2) fixture.inner->setMetadata(llvm::LLVMContext::MD_prof, llvm::MDNode::get(fixture.context,
            {llvm::MDString::get(fixture.context, "VP"), llvm::ConstantAsMetadata::get(builder.getInt32(0)),
             llvm::ConstantAsMetadata::get(builder.getInt64(101)), llvm::ConstantAsMetadata::get(builder.getInt64(123456)),
             llvm::ConstantAsMetadata::get(builder.getInt64(99))}));
        else if (mutation == 3) fixture.profile->replaceOperandWith(2, llvm::ConstantAsMetadata::get(builder.getInt64(101)));
        else if (mutation == 4) fixture.profile->replaceOperandWith(3,
            llvm::ConstantAsMetadata::get(builder.getInt64(0x8edcba9876543210ull)));
        else if (mutation == 5) fixture.profile->replaceOperandWith(1, llvm::ConstantAsMetadata::get(builder.getInt32(1)));
        else if (mutation == 6) fixture.outer->setMetadata(llvm::LLVMContext::MD_prof, nullptr);
        else if (mutation == 7) fixture.inner->setMetadata(llvm::LLVMContext::MD_prof, nullptr);
        else if (mutation == 8) fixture.inner->setMetadata(llvm::LLVMContext::MD_prof,
            llvm::MDNode::get(fixture.context, {llvm::MDString::get(fixture.context, "branch_weights"),
                llvm::ConstantAsMetadata::get(builder.getInt32(1))}));
        else if (mutation == 9) fixture.outer->setMetadata(llvm::LLVMContext::MD_prof,
            llvm::MDNode::get(fixture.context, {llvm::MDString::get(fixture.context, "branch_weights"),
                llvm::ConstantAsMetadata::get(builder.getInt32(1))}));
        else if (mutation == 10) fixture.outer->setMetadata("pyobf.frame.invoke", nullptr);
        else if (mutation == 11) fixture.inner->setMetadata("pyobf.frame.inner", nullptr);
        else if (mutation == 12) {
            builder.SetInsertPoint(fixture.inner);
            auto *duplicate = builder.CreateCall(fixture.target);
            duplicate->setMetadata("pyobf.frame.inner", fixture.descriptor);
        } else {
            builder.SetInsertPoint(fixture.outer);
            auto *duplicate = builder.CreateCall(fixture.helper, {fixture.outer->getArgOperand(0)});
            duplicate->setMetadata("pyobf.frame.invoke", fixture.descriptor);
        }
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || fixture.seal->verify(fixture.module).empty()) {
            llvm::errs() << "valid-IR frame profile mutation escaped: " << mutation << "\n"; return 1;
        }
    }
    for (unsigned mutation = 0; mutation < 4; ++mutation) {
        ProfileFixture fixture;
        if (mutation == 0) fixture.profile->replaceOperandWith(2,
            llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt64Ty(fixture.context), 101)));
        else if (mutation == 1) fixture.generated.at("helper").owner = "other";
        else if (mutation == 2) fixture.source->setMetadata("pyobf.frame.plan", nullptr);
        else fixture.inner->setMetadata(llvm::LLVMContext::MD_prof, nullptr);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || fixture.seal->bind(fixture.module, fixture.generated).empty()) return 1;
    }
    llvm::outs() << "verified frame profile matrices and 18 valid-IR mutations\n";
    return 0;
}
