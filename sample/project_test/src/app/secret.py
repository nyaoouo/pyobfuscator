"""Core licensed logic — PROTECTED (shipped as an encrypted blob + stub; do not hand-edit the build
output, rebuild via build_project.py). The license key is injected at build time via precompile_arg and
folded through precompile, so neither the key literal nor "the key is scrambled" survives in the source
or the (decrypted) body — only the precomputed digest tuple remains."""
from pyobfuscator import precompile, precompile_arg


def _scramble(text):
    codes = []
    for index, character in enumerate(text):
        codes.append((ord(character) + index * 3) % 256)
    return tuple(codes)


def license_ok(key):
    # The right-hand side is computed at BUILD time: precompile_arg injects the license key (build
    # script supplies precompile_args={"LICENSE_KEY": ...}; the "PYOBF-PRO-2026" default lets the
    # un-obfuscated source run for devs), then precompile folds _scramble(key) into a constant tuple.
    return _scramble(key) == precompile(_scramble(precompile_arg("LICENSE_KEY", "PYOBF-PRO-2026")))


def core_transform(payload):
    return payload[::-1].upper()
