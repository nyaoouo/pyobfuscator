"""Seal early-fixed scoped material under a complete live-code-derived key."""
import hashlib

from archive_format import Kind, Record
from measured_release import expansion
from pack_archive import seal, verify_bytes

DOMAIN = b"pyobf.native.contribution.scope.material.v1\0"


def material_key(words, identity, digest):
    if identity.stage != 2:
        raise ValueError("scoped material requires a post-release reference")
    return hashlib.sha256(DOMAIN + expansion(words, identity, digest)).digest()


def build_material(material, words, identity, digest):
    if type(material) is not bytes or len(material) != 32:
        raise ValueError("scoped material must contain32 immutable early-fixed bytes")
    return seal([Record("measured-material", Kind.bytes, 8, 1, 0, material)],
        keys=(material_key(words, identity, digest),)).data


def verify_material(package, material, words, identity, digest):
    if type(material) is not bytes or len(material) != 32:
        raise ValueError("scoped material must contain32 immutable early-fixed bytes")
    verify_bytes(package, material, material_key(words, identity, digest))
