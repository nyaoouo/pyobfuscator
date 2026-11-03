#pragma once

#include "call_frames.hpp"

namespace llvm { class GetElementPtrInst; }

namespace pyobfuscator::native::cff {

struct FramePlacement {
    unsigned offset, alignment, placements;
};
std::optional<FramePlacement> frame_placement(const llvm::DataLayout &, const FrameLayout &, unsigned);
llvm::GetElementPtrInst *emit_prepared_address(llvm::GetElementPtrInst &, llvm::Value *, std::uint32_t);
bool preparation_state_routes_to(const llvm::BasicBlock &, const llvm::AllocaInst *, std::uint32_t);
std::vector<InstructionSite> discover_call_preparation(llvm::Function &, const ResolvedRecipe &);
unsigned normalize_call_preparation(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
unsigned prepare_call_steps(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
unsigned bind_call_addresses(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t, SiteCoverage *);
std::optional<unsigned> prepared_frame_field(const llvm::GetElementPtrInst &, const llvm::Value *, const FrameLayout &);
std::string verify_call_preparation(const llvm::Module &);
void reject_preparation_artifacts(const llvm::Module &);
void strip_call_preparation(llvm::Module &);

}  // namespace pyobfuscator::native::cff
