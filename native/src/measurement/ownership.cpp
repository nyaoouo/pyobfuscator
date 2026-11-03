#include "capture.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement {

PYOBF_NATIVE_CFF_SDK void Capture::reset() noexcept {
    PYOBF_NATIVE_ERASE(&data_, sizeof(data_));
    data_.status = Status::unavailable;
    if (!PYOBF_NATIVE_CLOSE_CODE_VIEW(view_)) PYOBF_NATIVE_PROTECTION_FAILURE(0x702);
}

PYOBF_NATIVE_CFF_SDK void Capture::take(Capture &other) noexcept {
    view_ = other.view_;
    data_ = other.data_;
    other.view_ = {};
    PYOBF_NATIVE_ERASE(&other.data_, sizeof(other.data_));
    other.data_.status = Status::unavailable;
}

PYOBF_NATIVE_CFF_SDK Capture::Capture(Capture &&other) noexcept { take(other); }
PYOBF_NATIVE_CFF_SDK Capture &Capture::operator=(Capture &&other) noexcept {
    if (this != &other) { reset(); take(other); }
    return *this;
}
PYOBF_NATIVE_CFF_SDK Capture::~Capture() { reset(); }
PYOBF_NATIVE_CFF_SDK const Data &Capture::data() const noexcept { return data_; }
PYOBF_NATIVE_CFF_SDK void Capture::fail(Status status) noexcept { reset(); data_.status = status; }

}  // namespace pyobfuscator::native::measurement
