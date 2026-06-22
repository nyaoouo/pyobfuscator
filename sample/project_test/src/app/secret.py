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


@precompile
def _LICENSE_DIGEST():
    # Computed at BUILD time. As a @precompile decorator on a zero-argument function, the obfuscator
    # runs this thunk and binds _LICENSE_DIGEST to the returned constant tuple (the `def` is replaced
    # by `_LICENSE_DIGEST = (...)`). precompile_arg injects the license key (build script supplies
    # precompile_args={"LICENSE_KEY": ...}; the "PYOBF-PRO-2026" default lets the un-obfuscated source
    # run for devs). Neither the key nor "_scramble was applied" survives in the obfuscated body.
    return _scramble(precompile_arg("LICENSE_KEY", "PYOBF-PRO-2026"))


def license_ok(key):
    return _scramble(key) == _LICENSE_DIGEST


def core_transform(payload):
    return payload[::-1].upper()
