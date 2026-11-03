#pragma once

#include "recipe.hpp"

#include <optional>

namespace llvm { class CallInst; class CallBase; class StructType; class MDNode; class AllocaInst; }

namespace pyobfuscator::native::cff {

struct FrameLayout {
    llvm::StructType *type;
    unsigned target, result;
    std::vector<unsigned> arguments;
    unsigned padding = ~0u;
};

struct FrameInfo {
    llvm::Function *helper, *target;
    FrameLayout layout;
    bool external = false;
};

FrameLayout call_frame_layout(const llvm::CallBase &, const ResolvedRecipe &);
std::string call_frame_reason(const llvm::CallBase &, const ResolvedRecipe &, bool external = false);
llvm::CallBase *emit_frame_dispatch(llvm::CallBase &, llvm::Function &, llvm::Value *,
                                     llvm::IRBuilder<> &, SiteCoverage &);
std::string validate_frame_completion(const llvm::Function &);
std::vector<InstructionSite> discover_frame_calls(llvm::Function &, const ResolvedRecipe &, bool external);
std::vector<InstructionSite> discover_call_frames(llvm::Function &, const ResolvedRecipe &);
void retain_call_frame_abis(llvm::Function &, const ResolvedRecipe &);
void plan_frame_component(llvm::Module &, const std::map<std::string, ResolvedRecipe> &,
                            std::vector<GeneratedDefinition> &, llvm::StringRef component);
void plan_call_frames(llvm::Module &, const std::map<std::string, ResolvedRecipe> &,
                        std::vector<GeneratedDefinition> &);
unsigned normalize_call_frames(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
unsigned normalize_frame_component(llvm::Function &, const ResolvedRecipe &, SiteCoverage &, llvm::StringRef component);
void hoist_call_frame_storage(llvm::Function &);
bool is_frame_field(const llvm::Value *, const llvm::Value *, const FrameLayout &, unsigned);
bool closed_frame_storage(const llvm::Value *, const FrameLayout &,
                            const std::set<const llvm::Instruction *> &);
llvm::MDNode *frame_metadata(llvm::Function *, llvm::Function *, const FrameLayout &);
std::optional<FrameInfo> read_frame_metadata(const llvm::MDNode *);
std::optional<unsigned> frame_number(const llvm::MDNode *, unsigned);
std::string verify_call_frames(const llvm::Module &);
void reject_call_frame_artifacts(const llvm::Module &);
void finish_call_frames(llvm::Module &);

}  // namespace pyobfuscator::native::cff
