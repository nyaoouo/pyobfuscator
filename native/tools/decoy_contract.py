"""Constrained decoy input/identity boundary; no runtime authorization dependencies."""

import hashlib
import json
import re

from release_plan import child_identity

DOMAIN = b"pyobf.native.decoy.v1\0"


def _unique(fields):
    result = {}
    for key, value in fields:
        if key in result:
            raise ValueError("duplicate decoy source coverage field")
        result[key] = value
    return result


def validate_ir(source: str) -> None:
    entries = re.findall(r"(?m)^define ([^\n]*?)@pyobf_native_inner_entry\(([^\n]*)\)[^\n]*\{", source)
    if len(entries) != 1:
        raise ValueError("decoy needs exactly one defined C entry")
    prefix, arguments = entries[0]
    if ("dllexport" not in prefix.split() or not prefix.rstrip().endswith("i32") or
            re.search(r"\b(?:\w*cc|cc\s+\d+|signext|zeroext|weak\w*|linkonce\w*|available_externally)\b", prefix)):
        raise ValueError("decoy entry must export default-C i32 ABI")
    parameters = arguments.split(",")
    if (len(parameters) != 2 or not parameters[0].startswith("ptr ") or
            not parameters[1].strip().startswith("i32 ") or
            re.search(r"\b(?:sret|byval|inalloca|preallocated|signext|zeroext)\b", arguments)):
        raise ValueError("decoy entry needs pointer+i32 parameters without ABI adapters")
    if re.search(r"@llvm\.global_(?:ctors|dtors)\b|\bthread_local\b|(?m:^define [^\n]*@DllMain\()", source):
        raise ValueError("decoy TLS/authored DllMain/dynamic initialization is unsupported")
    if "@pyobf_native_path_fold_" in source or "@pyobf_native_demo_run" in source:
        raise ValueError("decoy image cannot depend on outer release/fold entry points")


def validate_child(image: bytes, coverage: bytes, report: bytes) -> tuple[str, str]:
    identity = child_identity(image, report)
    document, final = json.loads(coverage, object_pairs_hook=_unique), json.loads(report)
    if type(document) is not dict or document.get("domain") != "decoy-payload":
        raise ValueError("decoy child has the wrong CFF domain")
    if final.get("input_report_sha256") != hashlib.sha256(coverage).hexdigest():
        raise ValueError("decoy source coverage and final report identity differs")
    if not any(row["selected"] and row.get("function") == "pyobf_native_inner_entry" for row in final["functions"]):
        raise ValueError("decoy final coverage must include its declared entry")
    for row in final["functions"]:
        fold = row.get("path_fold", {})
        if type(fold) is not dict:
            raise ValueError("decoy final fold report is malformed")
        if fold.get("ir_binding_contract_verified"):
            raise ValueError("decoy child cannot require release-fold contributions")
    return identity


def authenticated_data(identity: tuple[str, str]) -> bytes:
    return DOMAIN + bytes.fromhex(identity[0]) + bytes.fromhex(identity[1])
