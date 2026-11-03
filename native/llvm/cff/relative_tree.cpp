#include "cff.hpp"

namespace pyobfuscator::native::cff {

extern const Strategy relative_tree_strategy{"relative-tree", validate_relative_tree, flatten};
extern const Strategy relative_tree_deep_strategy{"relative-tree-deep", validate_relative_tree_deep,
                                                  flatten_deep};

std::string validate_relative_tree_deep(const llvm::Function &function) {
    const auto reason = validate_relative_tree(function);
    if (!reason.empty()) {
        return reason;
    }
    if (!has_eligible_integer_constants(function) &&
        !has_eligible_internal_calls(function)) {
        return "relative-tree-deep needs an eligible scalar integer literal or internal call";
    }
    return {};
}

}  // namespace pyobfuscator::native::cff
