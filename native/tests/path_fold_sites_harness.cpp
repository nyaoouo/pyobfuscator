#include "path_fold/marker.hpp"
#include "path_fold/value.hpp"

#include <cstdio>

extern "C" void fold_whole(pyobfuscator::native::path_fold::Storage &, unsigned);
extern "C" void fold_hybrid(pyobfuscator::native::path_fold::Storage &, unsigned);
extern "C" void fold_loop(pyobfuscator::native::path_fold::Storage &);
extern "C" void fold_may_throw(unsigned mode) { if (mode != 0) throw mode; }

int main() {
    using namespace pyobfuscator::native::path_fold;
    for (unsigned choice = 0; choice != 32; ++choice) {
        Storage storage;
        fold_whole(storage, choice);
        auto expected = initialize(0x13579bdfu);
        expected = advance(expected, choice & 1 ? 0x101u : 0x102u, choice & 1 ? 0x912bca71u : 0x01234567u);
        expected = advance(expected, 0x103u, 0xa17e54c3u);
        std::printf("whole %u", choice);
        for (unsigned lane = 0; lane != 8; ++lane) {
            if (storage.words[lane] != expected[lane]) return 10;
            std::printf(" %u", storage.words[lane]);
        }
        std::puts("");
    }
    for (unsigned mode = 0; mode != 3; ++mode) {
        Storage storage;
        bool caught = false;
        try { fold_hybrid(storage, mode); }
        catch (unsigned error) { if (error != 2) return 11; caught = true; }
        if (caught != (mode == 2)) return 12;
        auto expected = initialize(0x2468ace0u);
        expected = advance(expected, mode == 0 ? 0x201u : 0x202u, mode == 0 ? 0x8a7351bdu : 0xc51a973du);
        if (mode != 2) expected = advance(expected, 0x203u, 0x715c3f91u);
        std::printf("hybrid %u", mode);
        for (unsigned lane = 0; lane != 8; ++lane) {
            if (storage.words[lane] != expected[lane]) return 13;
            std::printf(" %u", storage.words[lane]);
        }
        std::puts("");
    }
    Storage storage;
    fold_loop(storage);
    auto expected = initialize(0x3179bdf5u);
    for (unsigned index = 0; index != 3; ++index) expected = advance(expected, 0x301u, 0x6173b9d1u);
    std::printf("loop 3");
    for (unsigned lane = 0; lane != 8; ++lane) {
        if (storage.words[lane] != expected[lane]) return 14;
        std::printf(" %u", storage.words[lane]);
    }
    std::puts("");
}
