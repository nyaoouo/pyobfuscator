#pragma once

#include "reference_routes.hpp"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_import_sites(llvm::Function &, const ResolvedRecipe &);
unsigned normalize_import_routes(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
unsigned prepare_import_routes(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
unsigned bind_import_routes(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t, SiteCoverage *);
const llvm::Function *resolve_import_route(const llvm::LoadInst *, const llvm::GetElementPtrInst *,
    const llvm::AllocaInst *, const ReferenceInfo &);

}  // namespace pyobfuscator::native::cff
