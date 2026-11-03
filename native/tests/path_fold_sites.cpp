#include "path_fold/marker.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

extern "C" void fold_may_throw(unsigned);

extern "C" PYOBF_NATIVE_CFF void fold_loop(pyobfuscator::native::path_fold::Storage &storage) {
    pyobf_native_path_fold_init_v1(storage, 0x3179bdf5u);
    for (unsigned index = 0; index != 3; ++index)
        pyobf_native_path_fold_step_v1(storage, 0x301u, 0x6173b9d1u);
}

extern "C" PYOBF_NATIVE_CFF void fold_whole(pyobfuscator::native::path_fold::Storage &storage, unsigned choice) {
    pyobf_native_path_fold_init_v1(storage, 0x13579bdfu);
    if (choice & 1) pyobf_native_path_fold_step_v1(storage, 0x101u, 0x912bca71u);
    else pyobf_native_path_fold_step_v1(storage, 0x102u, 0x01234567u);
    pyobf_native_path_fold_step_v1(storage, 0x103u, 0xa17e54c3u);
}

extern "C" PYOBF_NATIVE_CFF void fold_hybrid(pyobfuscator::native::path_fold::Storage &storage, unsigned mode) {
    pyobf_native_path_fold_init_v1(storage, 0x2468ace0u);
    try {
        fold_may_throw(mode);
        pyobf_native_path_fold_step_v1(storage, 0x201u, 0x8a7351bdu);
    } catch (unsigned error) {
        pyobf_native_path_fold_step_v1(storage, 0x202u, 0xc51a973du);
        if (error == 2) throw;
    }
    pyobf_native_path_fold_step_v1(storage, 0x203u, 0x715c3f91u);
}
