#pragma once

#include "recipe.hpp"

namespace llvm { class AllocaInst; class GetElementPtrInst; class MDNode; }

namespace pyobfuscator::native::cff {

struct LocalUse { llvm::Instruction *instruction; unsigned operand; };
struct LocalObject {
    llvm::AllocaInst *storage;
    std::vector<LocalUse> uses;
    unsigned control_uses = 0;
    std::string reason;
};
struct LocalInfo {
    unsigned slot;
    std::uint64_t count, alignment;
    llvm::Type *type;
    std::string site;
    unsigned routes, controls;
};

bool local_control_use(const llvm::Instruction &);
bool compiler_local_storage(const llvm::AllocaInst &);
std::vector<LocalObject> collect_local_objects(llvm::Function &, const ResolvedRecipe &);
std::vector<InstructionSite> discover_indexed_locals(llvm::Function &, const ResolvedRecipe &);
std::optional<LocalInfo> local_info(const llvm::MDNode *);
llvm::MDNode *local_descriptor(llvm::AllocaInst &, unsigned, unsigned, unsigned);
unsigned normalize_indexed_locals(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);
void hoist_local_storage(llvm::Function &);
unsigned prepare_indexed_locals(llvm::Function &, llvm::Value *, const ResolvedRecipe &, SiteCoverage &);
unsigned bind_indexed_locals(llvm::BasicBlock &, llvm::Value *, std::uint32_t, std::uint32_t, SiteCoverage *);
std::optional<std::vector<const llvm::AllocaInst *>> local_table_targets(const llvm::AllocaInst *);
const llvm::AllocaInst *resolve_local_target(const llvm::Value *);
std::string verify_indexed_locals(const llvm::Module &);
void reject_local_artifacts(const llvm::Module &);
void strip_indexed_locals(llvm::Module &);

}  // namespace pyobfuscator::native::cff
