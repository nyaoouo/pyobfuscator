#include "contribution_expression.hpp"
#include "path_fold.hpp"
#include "transition_encode.hpp"

#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

llvm::Value *emit_contribution_delta(llvm::IRBuilder<> &builder, llvm::Value *current,
    llvm::Value *observed, std::uint32_t sealed, std::uint32_t contribution_salt,
    std::uint32_t transition_salt) {
    if (current == nullptr || !current->getType()->isIntegerTy(32) ||
            observed == nullptr || !observed->getType()->isIntegerTy(32))
        llvm::report_fatal_error("contribution correction needs i32 state and observation");
    auto *encoded = emit_path_fold_word(builder, observed, sealed, contribution_salt);
    return decode_delta(builder, current, encoded, transition_salt);
}

}  // namespace pyobfuscator::native::cff
