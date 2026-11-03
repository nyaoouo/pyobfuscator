#include "marker.hpp"
#include "value.hpp"

extern "C" void pyobf_native_path_fold_init_v1(pyobfuscator::native::path_fold::Storage &storage,
                                               std::uint32_t seed) noexcept {
    const auto state = pyobfuscator::native::path_fold::initialize(seed);
    volatile auto *words = storage.words;
    for (unsigned index = 0; index != state.size(); ++index) words[index] = state[index];
}

extern "C" void pyobf_native_path_fold_step_v1(pyobfuscator::native::path_fold::Storage &storage,
                                               std::uint32_t tag, std::uint32_t word) noexcept {
    pyobfuscator::native::path_fold::State before{};
    volatile auto *words = storage.words;
    for (unsigned index = 0; index != before.size(); ++index) before[index] = words[index];
    const auto after = pyobfuscator::native::path_fold::advance(before, tag, word);
    for (unsigned index = 0; index != after.size(); ++index) words[index] = after[index];
}
