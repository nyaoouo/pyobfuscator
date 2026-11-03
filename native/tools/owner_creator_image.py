"""Exact final creator code for early owner bindings; consumes the existing emission receipt."""
import hashlib

from function_inventory import Ownership, helpers
from function_subject import function_subject
from owner_reader_plan import readers
from pe_layout import parse_image


def verify_owner_creators(data, compiler_report, report_bytes, object_data, manifest, plan, reader_proof):
    proof = compiler_report.get("owner_creators")
    if (type(proof) is not dict or set(proof) != {"schema_version", "scheme", "entries"} or
            type(proof["schema_version"]) is not int or proof["schema_version"] != 1 or
            proof["scheme"] != "source-owned-creator-v1" or type(proof["entries"]) is not list or
            len(proof["entries"]) != len(plan.records)):
        raise ValueError("owner creator compiler inventory differs from its early plan")
    if (reader_proof.get("plan_sha256") != plan.digest.hex() or
            reader_proof.get("object_sha256") != hashlib.sha256(object_data).hexdigest()):
        raise ValueError("owner creator and reader final inputs differ")
    selected = {row["function"] for row in compiler_report["functions"] if row["selected"] and row["status"] == "transformed"}
    ownership = Ownership(manifest, report_bytes)
    image = parse_image(data)
    names = set()
    spans = []
    for row in reader_proof["entries"]:
        for role in ("capture", "cache"):
            name = row[role]
            subject = function_subject(object_data, data, image, row["index"] + 1, name)
            if not any(span.rva == row[role + "_rva"] for span in subject.ranges):
                raise ValueError("owner creator and reader final code locations differ")
            names.add(name)
            spans.extend((span.rva, span.size) for span in subject.ranges)
    entries = []
    for expected, row in zip(readers(plan), proof["entries"]):
        if (type(row) is not dict or set(row) != {"index", "owner", "plan_sha256", "function",
                "fixed_binding_row_verified", "direct_create_verified"} or
                type(row["index"]) is not int or row["index"] != expected.index or
                type(row["owner"]) is not int or row["owner"] != expected.owner or
                row["plan_sha256"] != plan.digest.hex() or
                row["fixed_binding_row_verified"] is not True or row["direct_create_verified"] is not True):
            raise ValueError("owner creator role/source evidence differs from its early plan")
        name = row["function"]
        if type(name) is not str or name not in selected or name in names:
            raise ValueError("owner creator is absent, shared or unselected")
        names.add(name)
        if helpers(object_data, ownership, name):
            raise ValueError("owner creator helper composition needs its own complete dataflow contract")
        subject = function_subject(object_data, data, image, expected.index + 1, name)
        for span in subject.ranges:
            if any(span.rva < start + size and start < span.rva + span.size for start, size in spans):
                raise ValueError("owner creator final functions overlap")
            spans.append((span.rva, span.size))
        entries.append({"index": expected.index, "owner": expected.owner, "function": name,
            "ranges": [{"rva": span.rva, "size": span.size} for span in subject.ranges]})
    return {"schema_version": 1, "verification_scope": "complete-fixed-creator-code-contributions",
        "object_sha256": hashlib.sha256(object_data).hexdigest(),
        "compiler_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "plan_sha256": plan.digest.hex(), "entries": entries}
