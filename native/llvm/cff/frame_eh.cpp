#include "call_frames.hpp"
#include "site_report.hpp"
#include "frame_profile.hpp"
#include "contribution_edges.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

llvm::CallBase *emit_frame_dispatch(llvm::CallBase &source, llvm::Function &helper,
                                     llvm::Value *frame, llvm::IRBuilder<> &builder,
                                     SiteCoverage &coverage) {
    if (auto *invoke = llvm::dyn_cast<llvm::InvokeInst>(&source)) {
        auto *normal = invoke->getNormalDest();
        auto *completion = llvm::BasicBlock::Create(source.getContext(), "pyobf.frame.complete", source.getFunction(), normal);
        llvm::IRBuilder<>(completion).CreateBr(normal);
        normal->replacePhiUsesWith(source.getParent(), completion);
        auto *dispatch = builder.CreateInvoke(&helper, completion, invoke->getUnwindDest(), {frame});
        dispatch->setDebugLoc(source.getDebugLoc());
        dispatch->setMetadata(llvm::LLVMContext::MD_prof, frame_profiles(source).outer);
        if (const auto reason = coverage.exceptional_origins().replace(*invoke, *dispatch); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(reason));
        if (coverage.contribution_edges)
            if (const auto reason = coverage.contribution_edges->replace_invoke(*invoke, *dispatch, *completion); !reason.empty())
                llvm::report_fatal_error(llvm::StringRef(reason));
        coverage.origins().set(*completion, BlockRole::routing);
        // The caller loads its typed result only after a normal helper return.
        builder.SetInsertPoint(completion->getTerminator());
        return dispatch;
    }
    auto *dispatch = builder.CreateCall(&helper, {frame});
    dispatch->setMetadata(llvm::LLVMContext::MD_prof, frame_profiles(source).outer);
    return dispatch;
}

}  // namespace pyobfuscator::native::cff
