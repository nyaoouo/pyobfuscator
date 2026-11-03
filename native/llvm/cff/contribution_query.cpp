#include "contribution_query.hpp"
#include "contribution_private.hpp"
#include "recipe.hpp"
#include "llvm/IR/Function.h"

namespace pyobfuscator::native::cff {
llvm::StringRef contribution_marker_name(const ResolvedRecipe &recipe) {
    return recipe.contribution && recipe.contribution->provider == "measured-scope-v1" ?
        "pyobf_native_measured_contribution_site_v1" : "pyobf_native_contribution_site_v1";
}
llvm::StringRef contribution_query_name(const llvm::Function &function) {
    if (!function.hasFnAttribute("pyobf.contribution.scope")) return "pyobf_native_contribution_word_v1";
    return function.getFnAttribute("pyobf.contribution.scope").getValueAsString() == "v1" ?
        "pyobf_native_measured_contribution_word_v1" : "";
}
llvm::StringRef contribution_group_query_name(llvm::StringRef provider, std::uint32_t schema) {
    const bool measured = provider == "measured-scope-v1";
    if (schema == 4) return measured ? "pyobf_native_mixed_measured_contribution_word_v1" :
        "pyobf_native_mixed_owned_contribution_word_v1";
    return measured ? "pyobf_native_measured_contribution_word_v1" : "pyobf_native_contribution_word_v1";
}
bool reserved_contribution_query(llvm::StringRef name) {
    return name == "pyobf_native_contribution_word_v1" || name == "pyobf_native_measured_contribution_word_v1" ||
        name == "pyobf_native_mixed_owned_contribution_word_v1" ||
        name == "pyobf_native_mixed_measured_contribution_word_v1";
}
}
