"""Version1 ordered u32 fold for build references; this is not a cryptographic digest."""

from __future__ import annotations

import struct

VERSION = 1
LANES = 8
MASK = (1 << 32) - 1


def _word(value: int) -> int:
    if type(value) is not int or not 0 <= value <= MASK:
        raise ValueError("path-fold words must be unsigned32 integers")
    return value


def _state(values) -> tuple[int, ...]:
    values = tuple(values)
    if len(values) != LANES:
        raise ValueError("path-fold state must contain eight words")
    return tuple(_word(value) for value in values)


def _rotate(value: int, count: int) -> int:
    count %= 32
    return ((value << count) | ((value & MASK) >> ((32 - count) % 32))) & MASK


def _mix(value: int) -> int:
    value &= MASK
    value = ((value ^ (value >> 16)) * 0x7FEB352D) & MASK
    value = ((value ^ (value >> 15)) * 0x846CA68B) & MASK
    return value ^ (value >> 16)


def initialize(seed: int) -> tuple[int, ...]:
    seed = _word(seed)
    return tuple(_mix(seed + 0x9E3779B9 * (lane + 1)) for lane in range(LANES))


def advance(before, tag: int, word: int) -> tuple[int, ...]:
    before, tag, word = _state(before), _word(tag), _word(word)
    event, label = _mix(word ^ 0x9E3779B9), _mix(tag ^ 0xD1B54A35)
    after = []
    for lane in range(LANES):
        value = _rotate((before[lane] + (event ^ before[(lane + 1) % LANES]) +
                         0x9E3779B9 * (lane + 1)) & MASK, 5 + 3 * lane)
        after.append(((value ^ _rotate((before[(lane + 3) % LANES] + label) & MASK, 7)) +
                      _rotate((event + before[(lane + 5) % LANES] +
                               _rotate(label, 1 + 3 * lane)) & MASK, 13)) & MASK)
    return tuple(after)


def encode_word(normal: int, expected_state: int, salt: int) -> int:
    return _word(normal) ^ _mix(_word(expected_state) ^ _word(salt))


def decode_word(encoded: int, current_state: int, salt: int) -> int:
    return _word(encoded) ^ _mix(_word(current_state) ^ _word(salt))


def serialize(state) -> bytes:
    return struct.pack("<8I", *_state(state))
