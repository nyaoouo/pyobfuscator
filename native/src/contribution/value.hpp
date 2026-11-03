#pragma once

#include "../path_fold/value.hpp"

#include <cstdint>

namespace pyobfuscator::native::contribution {

inline constexpr std::uint32_t version = 1;
struct State { std::uint32_t left, right, words; };

// This ordered word mixer is local obfuscation, not a hash or source validator.
// Acquisition, independent references and observation lifetime are separate contracts.
constexpr State absorb(const State &before, std::uint32_t label, std::uint32_t word) noexcept {
    const auto value = path_fold::mix(word ^ 0x9e3779b9u);
    const auto tag = path_fold::mix(label ^ 0xd1b54a35u);
    return {path_fold::rotate(before.left + value + before.words, 7) ^ (before.right + tag),
            path_fold::rotate(before.right ^ tag, 11) + (before.left ^ value), before.words + 1};
}

constexpr State initialize(std::uint32_t domain, std::uint32_t function, std::uint32_t site) noexcept {
    return absorb({path_fold::mix(domain ^ 0x243f6a88u), path_fold::mix(function ^ 0x85a308d3u), 0}, version, site);
}

constexpr State source(const State &before, std::uint32_t label, std::uint32_t encoding,
                        std::uint32_t word_count) noexcept {
    auto state = absorb(before, 0x53524301u, label);
    state = absorb(state, 0x53524302u, encoding);
    return absorb(state, 0x53524303u, word_count);
}

constexpr State word(const State &before, std::uint32_t value) noexcept {
    return absorb(before, 0x574f5244u, value);
}

constexpr std::uint32_t finish(const State &state) noexcept {
    return path_fold::mix(state.left ^ path_fold::rotate(state.right, 13) ^ path_fold::mix(state.words));
}

// expected is supplied only by the independent build reference. The emitted consumer
// receives sealed plus the actual observation, never a runtime expected-value lookup.
constexpr std::uint32_t seal(std::uint32_t encoded_delta, std::uint32_t expected, std::uint32_t salt) noexcept {
    return path_fold::encode_word(encoded_delta, expected, salt);
}

constexpr std::uint32_t unseal(std::uint32_t sealed, std::uint32_t observed, std::uint32_t salt) noexcept {
    return path_fold::decode_word(sealed, observed, salt);
}

}  // namespace pyobfuscator::native::contribution
