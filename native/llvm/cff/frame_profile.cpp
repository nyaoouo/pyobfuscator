#include "frame_profile.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff {

FrameProfiles frame_profiles(const llvm::CallBase &source) {
    auto *profile = source.getMetadata(llvm::LLVMContext::MD_prof);
    const auto *kind = profile == nullptr || profile->getNumOperands() < 2 ? nullptr :
        llvm::dyn_cast<llvm::MDString>(profile->getOperand(0));
    if (kind == nullptr || kind->getString() != "branch_weights") return {nullptr, profile};
    // isBranchWeightMD does not classify a single call-count operand. Read the
    // canonical tag and optional expected marker for both valid call forms.
    const auto first = llvm::isa<llvm::MDString>(profile->getOperand(1)) ? 2u : 1u;
    // Both generated calls execute once per original call. Two invoke weights
    // describe normal/unwind edges and cannot be attached to the inner CallInst.
    return {profile, profile->getNumOperands() - first == 1 ? profile : nullptr};
}

std::string profile_snapshot(const llvm::MDNode *profile) {
    if (profile == nullptr) return {};
    std::string result;
    llvm::raw_string_ostream stream(result);
    // Without a module, LLVM uses stable in-process node identities rather than
    // slot numbers that change when CFF creates or strips unrelated metadata.
    profile->printTree(stream);
    return result;
}

FrameProfileSeal::FrameProfileSeal(const llvm::Module &module) : module_(&module) {
    for (const auto &function : module) for (const auto &block : function) for (const auto &instruction : block)
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
            const auto profiles = frame_profiles(*call);
            sources_.push_back({call, &function, call->getCalledFunction(),
                profile_snapshot(call->getMetadata(llvm::LLVMContext::MD_prof)),
                profile_snapshot(profiles.outer), profile_snapshot(profiles.inner)});
        }
}

}  // namespace pyobfuscator::native::cff
