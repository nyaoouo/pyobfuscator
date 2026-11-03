#pragma once

#include <string>

namespace llvm {
class Function;
class StringRef;
}

namespace pyobfuscator::native::cff {
struct ResolvedRecipe;
class SiteCoverage;

struct RegionStrategy {
    const char *name;
    std::string (*validate)(const llvm::Function &, llvm::StringRef, llvm::StringRef);
    void (*apply)(llvm::Function &, llvm::StringRef, llvm::StringRef, unsigned);
};

const RegionStrategy *find_region_strategy(llvm::StringRef name);
std::string validate_relative_tree_region(const llvm::Function &function,
                                          llvm::StringRef entry, llvm::StringRef exit);
void flatten_region(llvm::Function &function, llvm::StringRef entry,
                    llvm::StringRef exit, unsigned seed);
std::string flatten_region_configured(llvm::Function &, const ResolvedRecipe &, SiteCoverage &);

}  // namespace pyobfuscator::native::cff
