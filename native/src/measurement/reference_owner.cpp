#include "reference_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::reference {

PYOBF_NATIVE_CFF_SDK void Reference::reset() noexcept {
    auto *retired = allocation_;
    const auto size = allocation_size_;
    allocation_ = nullptr; allocation_size_ = 0;
    descriptor_ = {};
    PYOBF_NATIVE_ERASE(digest_, sizeof(digest_));
    status_ = Status::unavailable;
    if (retired != nullptr) { PYOBF_NATIVE_ERASE(retired, size); PYOBF_NATIVE_RELEASE(retired); }
}

PYOBF_NATIVE_CFF_SDK void Reference::take(Reference &other) noexcept {
    allocation_ = other.allocation_; allocation_size_ = other.allocation_size_;
    descriptor_ = other.descriptor_; status_ = other.status_;
    for (unsigned index = 0; index != 32; ++index) digest_[index] = other.digest_[index];
    other.allocation_ = nullptr; other.allocation_size_ = 0;
    other.descriptor_ = {}; other.status_ = Status::unavailable;
    PYOBF_NATIVE_ERASE(other.digest_, sizeof(other.digest_));
}

PYOBF_NATIVE_CFF_SDK Reference::Reference(Reference &&other) noexcept { take(other); }
PYOBF_NATIVE_CFF_SDK Reference &Reference::operator=(Reference &&other) noexcept {
    if (this != &other) { reset(); take(other); }
    return *this;
}
PYOBF_NATIVE_CFF_SDK Reference::~Reference() { reset(); }
PYOBF_NATIVE_CFF_SDK Status Reference::status() const noexcept { return status_; }
PYOBF_NATIVE_CFF_SDK const Descriptor &Reference::descriptor() const noexcept { return descriptor_; }
PYOBF_NATIVE_CFF_SDK const std::uint8_t *Reference::expected_digest() const noexcept { return digest_; }
PYOBF_NATIVE_CFF_SDK void Reference::fail(Status status) noexcept { reset(); status_ = status; }

}  // namespace pyobfuscator::native::measurement::reference
