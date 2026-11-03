#include "decoy.hpp"
#include "key_expansion.hpp"
#include "decoy_blob.hpp"

#include <cstring>

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP bool reconstruct_decoy_key(const DecoySession &session, std::uint8_t *key) noexcept {
    static_assert(sizeof(packed_decoy::record) == sizeof(release::Record));
    release::Record record;
    std::memcpy(&record, packed_decoy::record, sizeof(record));
    return expand_release_key(*session.fold, record, key);
}

}  // namespace pyobfuscator::native::demo
