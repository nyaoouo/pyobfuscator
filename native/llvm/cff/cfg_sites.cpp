#include "recipe.hpp"
#include "region_scope.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

std::vector<InstructionSite> discover_cfg_sites(llvm::Function &function, const ResolvedRecipe &recipe) {
    std::vector<InstructionSite> sites;
    for (auto &block : function) {
        if (recipe.region_scope && !recipe.region_scope->contains(block)) continue;
        if (recipe.coverage == "hybrid-eh" && llvm::isa<llvm::ResumeInst>(block.getTerminator())) continue;
        sites.push_back({block.getTerminator(), 0, {}});
    }
    return sites;
}

}  // namespace pyobfuscator::native::cff
