#pragma once

#include <array>
#include <cstdint>

namespace pyobfuscator::native::path_fold {

inline constexpr unsigned version = 1;
inline constexpr unsigned lanes = 8;
using State = std::array<std::uint32_t, lanes>;
using Bytes = std::array<std::uint8_t, lanes * 4>;

constexpr std::uint32_t rotate(std::uint32_t value, unsigned count) noexcept {
    count &= 31;
    return (value << count) | (value >> ((32 - count) & 31));
}

constexpr std::uint32_t mix(std::uint32_t value) noexcept {
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    return value ^ (value >> 16);
}

constexpr State initialize(std::uint32_t seed) noexcept {
    State state{};
    for (unsigned index = 0; index != lanes; ++index)
        state[index] = mix(seed + 0x9e3779b9u * (index + 1));
    return state;
}

// This is an ordered obfuscation fold, not a cryptographic hash or a secret.
// Every output uses the previous snapshot; in-place sequential lane updates differ.
constexpr State advance(const State &before, std::uint32_t tag, std::uint32_t word) noexcept {
    State after{};
    const auto event = mix(word ^ 0x9e3779b9u);
    const auto label = mix(tag ^ 0xd1b54a35u);
    for (unsigned index = 0; index != lanes; ++index) {
        const auto value = rotate(before[index] + (event ^ before[(index + 1) % lanes]) +
                                  0x9e3779b9u * (index + 1), 5 + 3 * index);
        after[index] = (value ^ rotate(before[(index + 3) % lanes] + label, 7)) +
                       rotate(event + before[(index + 5) % lanes] + rotate(label, 1 + 3 * index), 13);
    }
    return after;
}

constexpr std::uint32_t encode_word(std::uint32_t normal, std::uint32_t expected_state,
                                    std::uint32_t salt) noexcept {
    return normal ^ mix(expected_state ^ salt);
}

constexpr std::uint32_t decode_word(std::uint32_t encoded, std::uint32_t current_state,
                                    std::uint32_t salt) noexcept {
    return encoded ^ mix(current_state ^ salt);
}

constexpr Bytes serialize(const State &state) noexcept {
    Bytes bytes{};
    for (unsigned index = 0; index != bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>(state[index / 4] >> (8 * (index % 4)));
    return bytes;
}

}  // namespace pyobfuscator::native::path_fold
