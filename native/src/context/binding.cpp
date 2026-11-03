#include "publication.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native {

PYOBF_NATIVE_CFF_SDK BootstrapContextBinding::BootstrapContextBinding() noexcept = default;
PYOBF_NATIVE_CFF_SDK BootstrapContextBinding::BootstrapContextBinding(detail::ContextPublication *origin,
    std::uint64_t serial, std::uint64_t generation) noexcept
    : publication_(origin), serial_(serial), generation_(generation) {}
PYOBF_NATIVE_CFF_SDK BootstrapContextBinding::BootstrapContextBinding(BootstrapContextBinding &&other) noexcept
    : publication_(other.publication_), serial_(other.serial_), generation_(other.generation_) {
    other.publication_ = nullptr;
    other.serial_ = other.generation_ = 0;
}
PYOBF_NATIVE_CFF_SDK BootstrapContextBinding &BootstrapContextBinding::operator=(BootstrapContextBinding &&other) noexcept {
    if (this == &other) return *this;
    BootstrapContextBinding previous(publication_, serial_, generation_);
    publication_ = other.publication_;
    serial_ = other.serial_;
    generation_ = other.generation_;
    other.serial_ = other.generation_ = 0;
    other.publication_ = nullptr;
    return *this;
}
PYOBF_NATIVE_CFF_SDK BootstrapContextBinding::~BootstrapContextBinding() { reset(); }
PYOBF_NATIVE_CFF_SDK void BootstrapContextBinding::reset() noexcept {
    const auto previous = serial_;
    auto *origin = publication_;
    publication_ = nullptr;
    serial_ = generation_ = 0;
    if (previous != 0) detail::release_publication(origin, previous);
}
PYOBF_NATIVE_CFF_SDK std::uint64_t BootstrapContextBinding::generation() const noexcept { return generation_; }

}  // namespace pyobfuscator::native
