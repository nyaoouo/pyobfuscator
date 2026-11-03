#include "descriptor.hpp"

namespace capture_test {
namespace {
bool number(FILE *input, unsigned bytes, std::uint64_t &value) {
    value = 0;
    for (unsigned byte = 0; byte != bytes; ++byte) {
        const int next = std::fgetc(input);
        if (next == EOF) return false;
        value |= std::uint64_t(next) << (byte * 8);
    }
    return true;
}
}

bool Parameters::read(const char *path) {
    auto *input = std::fopen(path, "rb");
    if (input == nullptr) return false;
    std::uint64_t words[7]{};
    bool ok = true;
    for (unsigned index = 0; index != 7; ++index)
        ok = ok && number(input, index == 4 ? 8 : 4, words[index]);
    ok = ok && words[5] > 0 && words[5] <= pyobfuscator::native::measurement::max_ranges &&
        words[6] <= pyobfuscator::native::measurement::max_fixups;
    if (ok) {
        ranges.resize(static_cast<std::size_t>(words[5]));
        fixups.resize(static_cast<std::size_t>(words[6]));
        for (auto &range : ranges) {
            std::uint64_t rva = 0, size = 0;
            ok = ok && number(input, 4, rva) && number(input, 4, size);
            range = {static_cast<std::uint32_t>(rva), static_cast<std::uint32_t>(size)};
        }
        for (auto &fixup : fixups) {
            std::uint64_t value = 0; ok = ok && number(input, 4, value);
            fixup = static_cast<std::uint32_t>(value);
        }
        ok = ok && std::fgetc(input) == EOF;
        value = {static_cast<std::uint32_t>(words[0]), static_cast<std::uint32_t>(words[1]),
            static_cast<std::uint32_t>(words[2]), static_cast<std::uint32_t>(words[3]), words[4],
            ranges.data(), static_cast<std::uint32_t>(ranges.size()), fixups.data(), static_cast<std::uint32_t>(fixups.size())};
    }
    return std::fclose(input) == 0 && ok;
}
}
