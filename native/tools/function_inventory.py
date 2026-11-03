"""Private emission provenance joining real CFF report, final IR and classic COFF bytes."""
from dataclasses import dataclass
import hashlib
import json

from coff_layout import parse_object
from generated_ownership import closure, graph
from reference_plan import _object, _unique


@dataclass(frozen=True)
class Ownership:
    manifest: bytes
    report: bytes


def _hash(data): return hashlib.sha256(data).hexdigest()


def create(object_data, ir, report):
    if type(ir) is not bytes or not 0 < len(ir) <= 128 * 1024 * 1024:
        raise ValueError("function inventory needs bounded immutable final IR")
    rows, edges = graph(report)
    obj = parse_object(object_data)
    functions = {}
    for symbol in obj.symbols:
        if symbol.type == 0x20 and symbol.section > 0: functions.setdefault(symbol.name, []).append(symbol)
    for name in {name for owner, helper, component, site in edges for name in (owner, helper)}:
        matches = functions.get(name, ())
        if len(matches) != 1 or matches[0].value != 0:
            raise ValueError("generated ownership requires actual separate compiler contributions")
    return json.dumps({"schema_version": 1, "object_sha256": _hash(object_data),
        "ir_sha256": _hash(ir), "report_sha256": _hash(report), "edges": [list(edge) for edge in edges]},
        sort_keys=True, separators=(",", ":")).encode()


def helpers(object_data, source, root):
    if (type(object_data) is not bytes or type(source) is not Ownership or type(source.manifest) is not bytes or
            type(source.report) is not bytes or not 0 < len(source.manifest) <= 16 * 1024 * 1024):
        raise ValueError("generated helper selection needs its private emission manifest and compiler report")
    manifest = json.loads(source.manifest, object_pairs_hook=_unique)
    _object(manifest, ("schema_version", "object_sha256", "ir_sha256", "report_sha256", "edges"))
    if (type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or
            manifest["object_sha256"] != _hash(object_data) or manifest["report_sha256"] != _hash(source.report) or
            type(manifest["ir_sha256"]) is not str or len(manifest["ir_sha256"]) != 64 or
            any(char not in "0123456789abcdef" for char in manifest["ir_sha256"])):
        raise ValueError("generated helper manifest is stale or belongs to another compiler artifact")
    rows, edges = graph(source.report)
    if manifest["edges"] != [list(edge) for edge in edges]:
        raise ValueError("generated helper manifest differs from its independent compiler report")
    return closure(rows, edges, root)


def main():
    import argparse
    from pathlib import Path
    from atomic_artifact import atomic_write
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("object", "ir", "report", "output"): parser.add_argument(name, type=Path)
    args = parser.parse_args()
    try:
        if len({path.resolve() for path in vars(args).values()}) != 4:
            raise ValueError("function inventory inputs/output must be distinct")
        atomic_write(args.output, create(args.object.read_bytes(), args.ir.read_bytes(), args.report.read_bytes()))
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
