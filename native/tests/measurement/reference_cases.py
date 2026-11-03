"""Real AEAD failures and authenticated malformed reference bodies, with independent inputs."""
from dataclasses import replace
import struct

from archive_format import Kind, Record
from code_reference import plaintext
from pack_archive import seal
from reference_identity import derive_key
from cff_build import run


def check_cases(args, directory, image_path, data, subject, identity, words, valid):
    metadata, package = directory / "case-metadata.bin", directory / "case-package.bin"
    command = [args.probe, metadata, package]
    suffix = [image_path] if image_path.resolve() != args.probe.resolve() else []
    count = 0

    def case(payload, status, *, expected=identity, material=words, match=True):
        nonlocal count
        # Invalid identities still need their raw bytes delivered to the native preflight.
        metadata.write_bytes(struct.pack("<16s16sIIIII8I", expected.build, expected.image,
            expected.owner, expected.subject, expected.kind, expected.stage, expected.capacity, *material))
        package.write_bytes(payload)
        run([*command, status, int(match), *suffix]); count += 1

    key = derive_key(identity, words)
    body = plaintext(data, subject, identity)

    def authenticated(offset, fmt, value, status):
        malformed = bytearray(body); struct.pack_into(fmt, malformed, offset, value)
        encrypted = seal([Record("code-reference-v1", Kind.bytes, 8, 1, 0, bytes(malformed))], keys=(key,)).data
        case(encrypted, status)

    case(bytes(len(valid)), 3)
    case(valid[:-1], 3)
    case(valid + b"\0", 3)
    for offset in (16, 80, 92, 104, 120, 136, len(valid) - 1):
        damaged = bytearray(valid); damaged[offset] ^= 1; case(bytes(damaged), 6)
    for name in ("build", "image"):
        for index in range(16):
            value = bytearray(getattr(identity, name)); value[index] ^= 1
            case(valid, 6, expected=replace(identity, **{name: bytes(value)}))
    for name, value in (("owner", identity.owner + 1), ("subject", identity.subject + 1), ("kind", 2), ("stage", 2)):
        case(valid, 6, expected=replace(identity, **{name: value}))
    for index in range(8):
        material = list(words); material[index] ^= 1; case(valid, 6, material=tuple(material))
    for name, value in (("build", bytes(16)), ("image", bytes(16)), ("owner", 0),
            ("subject", 0), ("kind", 4), ("stage", 0), ("capacity", 247), ("capacity", 512 * 1024 + 1)):
        case(valid, 2, expected=replace(identity, **{name: value}))
    for offset, value in ((0, 0), (16, 2), (20, 103), (24, 2), (96, 1), (len(body) - 4, 1)):
        authenticated(offset, "<I", value, 3)
    for offset in (28, 32, 36, 40): authenticated(offset, "<I", 99, 7)
    for offset, value in ((44, 0), (44, 1025), (48, 65537), (52, 63), (108, 0xffffffff)):
        authenticated(offset, "<I", value, 8)
    authenticated(56, "<Q", (1 << 64) - 1, 8)
    changed_digest = bytearray(body); changed_digest[64] ^= 1
    case(seal([Record("code-reference-v1", Kind.bytes, 8, 1, 0, bytes(changed_digest))], keys=(key,)).data,
        0, match=False)
    for invalid in ((), (bytes(31),), [bytes(32)], (bytearray(32),)):
        try: seal([Record("test", Kind.bytes, 8, 1, 0, b"test")], keys=invalid)
        except ValueError: count += 1
        else: raise AssertionError("invalid explicitly supplied archive key accepted")
    print(f"{count} independent identity/material/auth/body/failure cases incl observed-code mismatch pass")
