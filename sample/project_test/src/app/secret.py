"""Core licensed logic — PROTECTED (shipped as an encrypted blob + stub; do not hand-edit the build
output, rebuild via build_project.py). The license key literal and the transform live only here."""


def _scramble(text):
    codes = []
    for index, character in enumerate(text):
        codes.append((ord(character) + index * 3) % 256)
    return tuple(codes)


def license_ok(key):
    # position-dependent compare so the key never appears as a plain `key == "..."` literal
    return _scramble(key) == _scramble("PYOBF-PRO-2026")


def core_transform(payload):
    return payload[::-1].upper()
