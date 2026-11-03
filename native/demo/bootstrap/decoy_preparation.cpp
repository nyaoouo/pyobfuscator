#include "decoy.hpp"
#include "decoy_events_generated.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP bool advance_decoy_selection(DecoySession &session, int reason) noexcept {
    if (reason != -2 && reason != -4 && reason != -7 && reason != -8) return false;
    pyobf_native_path_fold_step_v1(*session.fold, decoy_events::environment_tag, decoy_events::environment_word);
    return true;
}

PYOBF_NATIVE_CFF_BOOTSTRAP void advance_decoy_preparation(DecoySession &session) noexcept {
    pyobf_native_path_fold_step_v1(*session.fold, decoy_events::support_tag, decoy_events::support_word);
}

}  // namespace pyobfuscator::native::demo
