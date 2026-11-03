#include "flow.hpp"
#include "buffer.hpp"
#include "path_events.hpp"
#include "pyobfuscator_native/system_ops.hpp"
#include "payload_blob.hpp"

#include <cstdint>
#include <cstring>

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP_EH int release_and_load_payload(bool corrupt, RuntimeSession &session) {
    if (!support_is_ready(session)) return -7;
    constexpr auto length = sizeof(packed::ciphertext);
    TransientBuffer sealed(length, false), plaintext(length, true);
    if (sealed.bytes == nullptr || plaintext.bytes == nullptr) return -3;
    std::memcpy(sealed.bytes, packed::ciphertext, length);
    if (corrupt) {
        sealed.bytes[0] ^= 1;
    }
    pyobf_native_path_fold_step_v1(session.context->fold, path_events::release_tag, path_events::release_word);
    TransientBuffer key(32, true);
    if (key.bytes == nullptr) return -3;
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
    if (!reconstruct_measured_payload_key(session, key.bytes)) return -8;
    if (!measured_release_is_ready(session)) return -8;
#else
    if (!reconstruct_payload_key(*session.context, key.bytes)) return -8;
#endif
    const bool authenticated = PYOBF_NATIVE_DECRYPT(
        sealed.bytes, length, key.bytes, packed::nonce, packed::tag, plaintext.bytes);
    key.reset();
    sealed.reset();
    if (!authenticated) return -4;
    if (!freeze_contribution(*session.context)) return -8;
    record_stage(2, session.context);

    session.image = PYOBF_NATIVE_LOAD(plaintext.bytes, length);
    plaintext.reset();
    if (session.image == nullptr) {
        return -5;
    }
    record_stage(3, session.context);
    return 0;
}

}  // namespace pyobfuscator::native::demo
