"""Actual owner callback code and readonly binding data; no symbol-size inference."""
import hashlib
import struct

from coff_layout import parse_object
from coff_relocations import Resolver, linked_bytes
from coff_symbols import image_symbols
from function_inventory import Ownership, helpers
from function_subject import function_subject
from owner_reader_plan import readers, symbol
from pe_layout import parse_image, read_rva, rva_section


def checker_arguments(object_path, inventory_path, plan_path):
    return ["--owner-object", object_path, "--owner-inventory", inventory_path, "--owner-plan", plan_path]


def verify_owner_readers(data, compiler_report, report_bytes, object_data, manifest, plan):
    proof = compiler_report.get("owner_readers")
    if (type(proof) is not dict or set(proof) != {"schema_version", "scheme", "entries"} or
            type(proof["schema_version"]) is not int or proof["schema_version"] != 1 or
            proof["scheme"] != "source-owned-reader-v1" or type(proof["entries"]) is not list or
            len(proof["entries"]) != len(plan.records)):
        raise ValueError("owner reader compiler inventory differs from its early plan")
    image, obj = parse_image(data), parse_object(object_data)
    resolver = Resolver(obj, image, image_symbols(data, image))
    ownership = Ownership(manifest, report_bytes)
    selected = {row["function"] for row in compiler_report["functions"] if row["selected"] and row["status"] == "transformed"}
    expected_symbol = symbol(plan)
    anchors = [item for item in obj.symbols if item.name == expected_symbol and item.type == 0 and item.section > 0]
    if len(anchors) != 1: raise ValueError("owner reader data needs its actual unique compiler definition")
    anchor = anchors[0]; section = obj.sections[anchor.section - 1]
    size = 32 * len(plan.records)
    if (anchor.value + size > section.size or section.flags & 0xa0000000 or not section.flags & 0x40000000):
        raise ValueError("owner reader bindings must be complete readonly nonexecuting data")
    base = resolver.named(expected_symbol)
    part = rva_section(image, base, size, logical=True)
    if part.flags & 0xa0000000 or not part.flags & 0x40000000:
        raise ValueError("owner reader final binding storage became writable or executable")
    linked = linked_bytes(object_data, obj, section, base - anchor.value, resolver)
    if linked[anchor.value:anchor.value + size] != read_rva(data, image, base, size):
        raise ValueError("owner reader final binding data differs after exact relocation evaluation")
    functions, spans, entries = set(), [], []
    fields = {"index", "owner", "key", "plan_sha256", "binding_symbol", "capture", "cache", "volatile_reads", "binding_stride",
        "ir_binding_verified", "ir_mapped_bytes_to_sha_verified", "early_key_comparison_verified"}
    for expected, row in zip(readers(plan), proof["entries"]):
        if (type(row) is not dict or set(row) != fields or type(row["index"]) is not int or row["index"] != expected.index or
                type(row["owner"]) is not int or row["owner"] != expected.owner or row["key"] != f"{expected.key:016x}" or
                row["plan_sha256"] != plan.digest.hex() or row["binding_symbol"] != expected_symbol or
                type(row["binding_stride"]) is not int or row["binding_stride"] != 32 or
                type(row["volatile_reads"]) is not int or not 0 < row["volatile_reads"] <= 65536 or
                any(row[key] is not True for key in ("ir_binding_verified", "ir_mapped_bytes_to_sha_verified", "early_key_comparison_verified"))):
            raise ValueError("owner reader role/domain/flow evidence differs from its frozen source")
        addresses = []
        for role in ("capture", "cache"):
            name = row[role]
            if type(name) is not str or name not in selected or name in functions:
                raise ValueError("owner reader roles are missing, shared or unselected")
            functions.add(name)
            if helpers(object_data, ownership, name):
                raise ValueError("owner reader helper composition needs its own complete dataflow contract")
            subject = function_subject(object_data, data, image, expected.index + 1, name)
            for span in subject.ranges:
                if any(span.rva < start + count and start < span.rva + span.size for start, count in spans):
                    raise ValueError("owner reader final functions are folded or overlap")
                spans.append((span.rva, span.size))
            addresses.append(resolver.named(name))
        actual = struct.unpack("<IIQQQ", read_rva(data, image, base + 32 * expected.index, 32))
        if actual != (1, expected.owner, expected.key, image.preferred_base + addresses[0], image.preferred_base + addresses[1]):
            raise ValueError("owner reader final function routing differs from its exact owner binding")
        entries.append({"index": expected.index, "owner": expected.owner, "capture_rva": addresses[0], "cache_rva": addresses[1],
            "binding_rva": base + 32 * expected.index, "capture": row["capture"], "cache": row["cache"]})
    return {"schema_version": 1, "verification_scope": "complete-callback-and-readonly-binding-contributions",
        "object_sha256": hashlib.sha256(object_data).hexdigest(), "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "plan_sha256": plan.digest.hex(), "compiler_report_sha256": hashlib.sha256(report_bytes).hexdigest(), "entries": entries}
