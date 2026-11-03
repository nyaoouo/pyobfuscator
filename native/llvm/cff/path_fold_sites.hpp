#pragma once

#include "recipe.hpp"
#include "llvm/IR/ValueHandle.h"

namespace llvm { class CallInst; }

namespace pyobfuscator::native::cff {
enum class FoldKind : unsigned { initialize, advance };
struct FoldMarker {
    llvm::CallInst *call = nullptr;
    FoldKind kind = FoldKind::initialize;
    std::uint32_t tag = 0, word = 0;
    std::string reason;
};
FoldMarker inspect_path_fold_marker(llvm::Instruction &);
std::vector<InstructionSite> discover_path_fold_sites(llvm::Function &, const ResolvedRecipe &);
void retain_path_fold_markers(llvm::Function &, const ResolvedRecipe &);
unsigned bind_path_fold_sites(llvm::BasicBlock &, llvm::Value *, std::uint32_t,
                               std::uint32_t, SiteCoverage *);
std::string validate_path_fold(const llvm::Function &);
struct StateLayout;
class PathFoldSeal {
public:
    PathFoldSeal(llvm::Function &, const StateLayout &, llvm::ArrayRef<InstructionSite> planned_sites);
    std::string verify(const llvm::Function &) const;
private:
    struct Expected {
        llvm::WeakTrackingVH storage;
        const llvm::BasicBlock *body;
        std::uint32_t state, word, tag;
        FoldKind kind;
    };
    const llvm::Function *owner_;
    std::map<std::string, Expected> expected_;
};
}
