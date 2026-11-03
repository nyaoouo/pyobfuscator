#pragma once

#include "recipe.hpp"

#include <optional>

namespace llvm { class GetElementPtrInst; class LoadInst; class MDNode; class Module; class AllocaInst; }

namespace pyobfuscator::native::cff {

struct ReferenceInfo {
    const llvm::Function *target;
    std::uint32_t slot, salt, state;
    bool call_target;
    bool imported = false;
};

const llvm::Function *reference_function(const llvm::Value *value);
std::string reference_reason(const llvm::Instruction &instruction, unsigned operand);
std::vector<InstructionSite> discover_reference_sites(llvm::Function &, const ResolvedRecipe &);
std::vector<InstructionSite> discover_function_references(llvm::Function &, const ResolvedRecipe &, bool imported);
unsigned normalize_reference_component(llvm::Function &, const ResolvedRecipe &, SiteCoverage &, bool imported);
unsigned normalize_reference_routes(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
void hoist_reference_storage(llvm::Function &);
unsigned prepare_reference_routes(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
unsigned bind_reference_routes(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t, SiteCoverage *);
unsigned bind_reference_component(llvm::BasicBlock &, llvm::Value *, std::uint32_t, SiteCoverage *, bool imported);
std::optional<std::vector<const llvm::Function *>> reference_table_targets(const llvm::AllocaInst *);
std::optional<ReferenceInfo> reference_info(const llvm::MDNode *node, bool bound);
const llvm::Function *resolve_reference_target(const llvm::Value *value);
std::string validate_reference_routes(const llvm::Function &function);
void reject_reference_artifacts(const llvm::Module &module);
void finish_reference_routes(llvm::Module &module);

}  // namespace pyobfuscator::native::cff
