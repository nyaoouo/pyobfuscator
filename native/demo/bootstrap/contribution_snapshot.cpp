#include "flow.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP bool freeze_contribution(RuntimeContext &context) noexcept {
    if (PYOBF_NATIVE_ATOMIC_CAS32(&context.contribution_state, 0, 1) != 0) return false;
    const volatile auto *source = context.fold.words;
    for (unsigned index = 0; index != 8; ++index) context.contribution_fold.words[index] = source[index];
    PYOBF_NATIVE_ATOMIC_STORE32(&context.contribution_state, 2);
    return true;
}

}  // namespace pyobfuscator::native::demo
