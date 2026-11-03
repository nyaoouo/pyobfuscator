#include "decoy.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP int finish_failed_release(RuntimeSession &session, int value, int reason, bool corrupt) {
#ifdef PYOBF_DEMO_ENABLE_DECOY
    if (reason != -2 && reason != -4 && reason != -7 && reason != -8) return reason;
    retire_payload(session);
    return release_decoy(value, reason, session.context, corrupt);
#else
    return reason;
#endif
}

}  // namespace pyobfuscator::native::demo
