#include "decoy.hpp"
#include "decoy_blob.hpp"
#include "decoy_events_generated.hpp"

#include <cstring>

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP_EH int release_decoy(int value, int reason, RuntimeContext *observer, bool corrupt) {
    DecoySession session;
    if (!initialize_decoy(session) || !advance_decoy_selection(session, reason)) return -9;
    constexpr auto length = sizeof(packed_decoy::ciphertext);
    static_assert(sizeof(packed_decoy::nonce) == 12 && sizeof(packed_decoy::tag) == 16);
    TransientBuffer sealed(length, true), plaintext(length, true), key(32, true);
    if (sealed.bytes == nullptr || plaintext.bytes == nullptr || key.bytes == nullptr) return -9;
    std::memcpy(sealed.bytes, packed_decoy::ciphertext, length);
    if (corrupt) sealed.bytes[0] ^= 1;
    advance_decoy_preparation(session);
    pyobf_native_path_fold_step_v1(*session.fold, decoy_events::release_tag, decoy_events::release_word);
    if (!reconstruct_decoy_key(session, key.bytes)) return -9;
    const bool authenticated = PYOBF_NATIVE_AEAD_DECRYPT(sealed.bytes, length, key.bytes,
        packed_decoy::nonce, packed_decoy::tag, packed_decoy::aad, sizeof(packed_decoy::aad), plaintext.bytes);
    key.reset();
    sealed.reset();
    if (!authenticated) return -9;
    record_stage(7, observer);
    session.image = PYOBF_NATIVE_LOAD(plaintext.bytes, length);
    plaintext.reset();
    if (session.image == nullptr) return -9;
    record_stage(8, observer);
    auto *entry = reinterpret_cast<DecoyEntry>(PYOBF_NATIVE_RESOLVE(session.image));
    if (entry == nullptr) return -9;
    const DecoyHandoff handoff{decoy_handoff_version, sizeof(DecoyHandoff), decoy_role, reason};
    const int result = entry(&handoff, value);
    record_stage(9, observer);
    session.reset();
    record_stage(10, observer);
    return result;
}

}  // namespace pyobfuscator::native::demo
