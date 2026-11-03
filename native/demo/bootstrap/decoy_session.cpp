#include "decoy.hpp"
#include "decoy_events_generated.hpp"

#include <new>

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP DecoySession::DecoySession() noexcept : storage(sizeof(path_fold::Storage), true) {
    if (storage.bytes != nullptr) fold = new (storage.bytes) path_fold::Storage{};
}

PYOBF_NATIVE_CFF_BOOTSTRAP DecoySession::~DecoySession() { reset(); }

PYOBF_NATIVE_CFF_BOOTSTRAP void DecoySession::reset() noexcept {
    if (image != nullptr) {
        PYOBF_NATIVE_UNLOAD(image);
        image = nullptr;
    }
}

PYOBF_NATIVE_CFF_BOOTSTRAP bool initialize_decoy(DecoySession &session) noexcept {
    if (session.fold == nullptr) return false;
    pyobf_native_path_fold_init_v1(*session.fold, decoy_events::seed);
    return true;
}

}  // namespace pyobfuscator::native::demo
