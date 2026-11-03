"""Early deterministic callback domains; no observed/final code value enters codegen."""
from dataclasses import dataclass
import hashlib
import struct


@dataclass(frozen=True)
class Reader:
    index: int
    owner: int
    key: int


def readers(plan):
    result, used = [], set()
    for index, record in enumerate(plan.records):
        key = int.from_bytes(hashlib.sha256(b"pyobf.native.owner.reader.v1\0" + plan.digest +
            struct.pack("<II", index, record.identity.owner)).digest()[:8], "little")
        if not key or key in used: raise ValueError("early owner-reader domains collide")
        used.add(key); result.append(Reader(index, record.identity.owner, key))
    return tuple(result)


def symbol(plan): return "pyobf_native_owner_bindings_" + plan.digest[:12].hex()


def namespace(plan): return "pyobfuscator::native::measurement::generated_" + plan.digest[:12].hex()


def creator_signature(index, named=False):
    if named:
        parameters = ('const std::uint8_t *package, std::size_t size, '
            'const reference::Identity &identity, const std::uint32_t (&words)[8], '
            'observer::Policy policy, platform::CodeAddress member, std::uint64_t instance')
    else:
        parameters = ('const std::uint8_t *, std::size_t, const reference::Identity &, '
            'const std::uint32_t (&)[8], observer::Policy, platform::CodeAddress, std::uint64_t')
    return f'observer::Creation create_{index}({parameters}) noexcept'


def render_header(plan):
    header = '#pragma once\n\n#include "measurement/observer.hpp"\n\n' + \
        f'extern "C" const pyobfuscator::native::measurement::observer::ReaderBinding {symbol(plan)}[{len(plan.records)}];\n'
    header += f'namespace {namespace(plan)} {{\n'
    for reader in readers(plan): header += f'{creator_signature(reader.index)};\n'
    header += '}\n'
    return header + \
        'namespace pyobfuscator::native::measurement::generated_readers {\n' + \
        f'inline constexpr auto *bindings = ::{symbol(plan)};\n' + \
        f'inline constexpr std::size_t count = {len(plan.records)};\n' + \
        ''.join(f'using {namespace(plan)}::create_{reader.index};\n' for reader in readers(plan)) + '}\n'


def render_source(plan):
    output = '#include "owner_readers.hpp"\n#include "measurement/owned_capture.hpp"\n' + \
        '#include "measurement/owner_cache.hpp"\n#include "pyobfuscator_native/cff_marker.hpp"\n\n' + \
        '#if defined(__clang__)\n#define PYOBF_OWNER_TAG(value) __attribute__((annotate(value)))\n' + \
        '#else\n#define PYOBF_OWNER_TAG(value)\n#endif\n\n'
    family = namespace(plan)
    output += f'namespace {family} {{\n'
    for reader in readers(plan):
        suffix = f'{reader.index}:{reader.owner}:{reader.key:016x}:{plan.digest.hex()}'
        output += f'PYOBF_NATIVE_CFF_SDK PYOBF_OWNER_TAG("pyobf.native.owner.capture.v1:{suffix}")\n' + \
            f'Capture capture_{reader.index}(const Descriptor &input, platform::CodeAddress member, std::uint64_t binding) noexcept {{\n' + \
            f'    return capture_owner<{reader.owner}u, 0x{reader.key:016x}ull>(input, member, binding);\n' + '}\n'
        output += f'PYOBF_NATIVE_CFF_SDK PYOBF_OWNER_TAG("pyobf.native.owner.cache.v1:{suffix}")\n' + \
            f'bool cache_{reader.index}(std::uint64_t binding, observer::Observation &record) noexcept {{\n' + \
            f'    return observer::transform_owner_cache<{reader.owner}u, 0x{reader.key:016x}ull>(binding, record);\n' + '}\n'
        output += f'PYOBF_NATIVE_CFF_SDK PYOBF_OWNER_TAG("pyobf.native.owner.creator.v1:{suffix}")\n' + \
            creator_signature(reader.index, named=True) + ' {\n' + \
            f'    if (identity.owner != {reader.owner}u) return {{{{observer::Status::invalid_specification}}, {{}}}};\n' + \
            f'    const observer::Spec spec{{policy, member, instance, &::{symbol(plan)}[{reader.index}]}};\n' + \
            '    return observer::create(package, size, identity, words, spec);\n}\n'
    output += '}\n\n' + f'extern "C" const pyobfuscator::native::measurement::observer::ReaderBinding {symbol(plan)}[] = {{\n'
    for reader in readers(plan):
        output += f'    {{1, {reader.owner}u, 0x{reader.key:016x}ull, &{family}::capture_{reader.index}, &{family}::cache_{reader.index}}},\n'
    return output + '};\n'
