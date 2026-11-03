#include "owner_readers.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace native = pyobfuscator::native;
namespace observer = native::measurement::observer;
namespace reference = native::measurement::reference;
namespace generated = native::measurement::generated_readers;

extern "C" PYOBF_NATIVE_CFF_SDK observer::Creation pyobf_test_owner_create(unsigned index,
        const std::uint8_t *package, std::size_t size, const reference::Identity &identity,
        const std::uint32_t (&words)[8], observer::Policy policy,
        native::platform::CodeAddress member, std::uint64_t instance) noexcept {
    switch (index) {
    case 0: return generated::create_0(package, size, identity, words, policy, member, instance);
    case 1: return generated::create_1(package, size, identity, words, policy, member, instance);
    case 2: return generated::create_2(package, size, identity, words, policy, member, instance);
    default: return {{observer::Status::invalid_specification}, {}};
    }
}
