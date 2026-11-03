"""Independent finite-width contribution-word reference, before provider integration."""

VERSION = 1
MASK = (1 << 32) - 1


def _word(value):
    if type(value) is not int or not 0 <= value <= MASK:
        raise ValueError("contribution word must be an unsigned32 integer")
    return value


def _state(value):
    if not isinstance(value, (tuple, list)) or len(value) != 3:
        raise ValueError("contribution state needs three words")
    return tuple(_word(word) for word in value)


def rotate(value, count):
    value = _word(value)
    count &= 31
    return ((value << count) | (value >> ((32 - count) & 31))) & MASK


def mix(value):
    value = _word(value)
    value = ((value ^ (value >> 16)) * 0x7FEB352D) & MASK
    value = ((value ^ (value >> 15)) * 0x846CA68B) & MASK
    return value ^ (value >> 16)


def absorb(state, label, word):
    left, right, count = _state(state)
    value, tag = mix(_word(word) ^ 0x9E3779B9), mix(_word(label) ^ 0xD1B54A35)
    return (rotate((left + value + count) & MASK, 7) ^ ((right + tag) & MASK),
            (rotate(right ^ tag, 11) + (left ^ value)) & MASK, (count + 1) & MASK)


def initialize(domain, function, site):
    return absorb((mix(_word(domain) ^ 0x243F6A88), mix(_word(function) ^ 0x85A308D3), 0), VERSION, site)


def source(state, label, encoding, word_count):
    for tag, value in ((0x53524301, label), (0x53524302, encoding), (0x53524303, word_count)):
        state = absorb(state, tag, value)
    return state


def word(state, value):
    return absorb(state, 0x574F5244, value)


def finish(state):
    left, right, count = _state(state)
    return mix(left ^ rotate(right, 13) ^ mix(count))


def seal(encoded_delta, expected, salt):
    return _word(encoded_delta) ^ mix(_word(expected) ^ _word(salt))


def unseal(sealed, observed, salt):
    return _word(sealed) ^ mix(_word(observed) ^ _word(salt))
