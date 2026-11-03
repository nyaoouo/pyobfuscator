#include "asset_sample.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

extern "C" __declspec(dllexport) PYOBF_NATIVE_CFF int read_asset(unsigned index) {
    const auto view = pyobfuscator::native::assets::get_sample();
    if (index >= view.size) return -1;
    return view.data[index];
}

extern "C" __declspec(dllexport) PYOBF_NATIVE_CFF unsigned optimized_literal(unsigned value) {
    unsigned offset = 41;
    return value + offset - offset;
}
