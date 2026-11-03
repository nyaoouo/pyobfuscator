#include "flow.hpp"
#include "key_expansion.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP bool reconstruct_payload_key(const RuntimeContext &context, std::uint8_t *key) noexcept {
    return expand_release_key(context.fold, release::record, key);
}

}  // namespace pyobfuscator::native::demo
