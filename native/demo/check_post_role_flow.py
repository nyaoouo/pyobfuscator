"""Exercise the actual POST producer proof with LLVM-valid wrong role flows."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from reference_plan import parse_plan
from reference_slots import storage


def run(command, *, succeeds=True):
    result = subprocess.run([str(part) for part in command], capture_output=True, text=True, timeout=90)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected tool result: {command}: {result.stderr[-1000:]}")
    return result


def replace_function(source, name, pattern, replacement):
    start = re.search(r"(?m)^define [^\n]*@" + re.escape(name) + r"\(", source)
    if start is None: raise AssertionError(f"actual producer is absent: {name}")
    end = source.index("\n}\n", start.start()) + 3
    body, count = re.subn(pattern, replacement, source[start.start():end], count=1)
    if count != 1 or body == source[start.start():end]:
        raise AssertionError(f"valid mutation did not select its unique site: {name}: {pattern}")
    return source[:start.start()] + body + source[end:]


def clobber(match):
    destination = re.search(r"ptr (?:align \d+ )?(%[A-Za-z0-9._]+)", match.group(0))
    if destination is None: raise AssertionError("actual role publication has no SSA destination")
    return match.group(0) + f"\n  store i32 0, ptr {destination[1]}, align 4"


def flip_status(match):
    return match.group(0).replace("icmp eq", "icmp ne") if "icmp eq" in match.group(0) else \
        match.group(0).replace("icmp ne", "icmp eq")


def main():
    parser = argparse.ArgumentParser()
    for name in ("opt", "plugin", "source", "requests", "configuration", "report", "plan", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("seed", type=int)
    args = parser.parse_args()
    document = json.loads(args.report.read_text(encoding="utf-8"))
    proof = document.get("post_role_flow")
    plan = parse_plan(args.plan.read_bytes())
    slots = storage(plan)
    if (type(proof) is not dict or set(proof) != {"schema_version", "plan_sha256", "roles"} or
            type(proof["schema_version"]) is not int or proof["schema_version"] != 1 or
            type(proof["plan_sha256"]) is not str or
            not re.fullmatch(r"[0-9a-f]{64}", proof["plan_sha256"]) or
            type(proof["roles"]) is not list or len(proof["roles"]) != 2):
        raise AssertionError("actual POST compiler report lacks two early roles")
    required = {"role", "creator_index", "owner", "producer", "creator", "routing_tag", "domain", "source",
        "code_offset", "material_offset",
        "creator_result_to_owner_verified", "owner_to_lease_verified", "lease_to_handoff_verified",
        "spec_identity_material_verified"}
    for role, row in enumerate(proof["roles"]):
        if (type(row) is not dict or set(row) != required or type(row["role"]) is not int or
                row["role"] != role or type(row["creator_index"]) is not int or
                row["creator_index"] != len(document["owner_creators"]["entries"]) - 2 + role or
                any(row[name] is not True for name in required if name.endswith("_verified")) or
                any(type(row[name]) is not int or not 0 < row[name] < 1 << 32
                    for name in ("owner", "routing_tag", "domain", "source"))):
            raise AssertionError("actual POST role source, slot or proof flags are malformed")
        creator = document["owner_creators"]["entries"][row["creator_index"]]
        if (row["creator"] != creator["function"] or row["owner"] != creator["owner"] or
                proof["plan_sha256"] != creator["plan_sha256"] or
                proof["plan_sha256"] != plan.digest.hex() or
                type(row["code_offset"]) is not int or type(row["material_offset"]) is not int or
                row["code_offset"] != slots.offsets[row["creator_index"]] or
                row["material_offset"] != slots.material_offsets[row["creator_index"]]):
            raise AssertionError("POST producer report does not match owner creator inventory")
    original = args.source.read_text(encoding="utf-8")
    first, second = proof["roles"]
    names = (first["producer"], second["producer"])
    identity = "@_ZN12pyobfuscator6native11measurement8reserved10identitiesE"
    data = "@_ZN12pyobfuscator6native11measurement8reserved4dataE"
    offsets = "@_ZN12pyobfuscator6native11measurement8reserved7offsetsE"
    material_offsets = "@_ZN12pyobfuscator6native11measurement8reserved16material_offsetsE"
    optimized = 'getelementptr inbounds nuw [2 x %"class.pyobfuscator::native::BootstrapContextOwner"]' not in original
    mutations = [
        ("swapped-creator", names[0], re.escape("@" + first["creator"]), "@" + second["creator"]),
        ("reversed-creator-status", names[0], r'icmp (?:eq|ne) i32 [^\n]+, 0', flip_status),
        ("wrong-owner-number", names[0], rf"i32 {first['owner']}(?=[,>])", f"i32 {first['owner'] + 1}"),
        ("ignored-first-role-result", "_ZN12pyobfuscator6native4demo12prepare_postERNS1_14RuntimeSessionEPFvvE",
            r'(%[A-Za-z0-9._]+ = (?:tail )?call[^\n]*@' + re.escape(names[0]) +
            r'\([^\n]*\)[^\n]*\n  br i1 )%[A-Za-z0-9._]+', r'\g<1>true'),
        ("missing-second-role", "_ZN12pyobfuscator6native4demo12prepare_postERNS1_14RuntimeSessionEPFvvE",
            re.escape("@" + names[1]), "@" + names[0]),
    ]
    if optimized:
        code_pointer = f"getelementptr inbounds nuw (i8, ptr {data}, i64 {first['code_offset']})"
        material_pointer = f"getelementptr inbounds nuw (i8, ptr {data}, i64 {first['material_offset']})"
        mutations.extend((
            ("extra-handoff-write", names[0], r'store <4 x i32> <[^\n]+', clobber),
            ("swapped-owner-slot", names[0], r'getelementptr inbounds nuw i8, ptr %0, i64 72\b',
                'getelementptr inbounds nuw i8, ptr %0, i64 80'),
            ("swapped-lease-slot", names[0], r'getelementptr inbounds nuw i8, ptr %0, i64 88\b',
                'getelementptr inbounds nuw i8, ptr %0, i64 104'),
            ("swapped-handoff-slot", names[0], r'getelementptr inbounds nuw i8, ptr %0, i64 136\b',
                'getelementptr inbounds nuw i8, ptr %0, i64 232'),
            ("wrong-spec-identity", names[0],
                r'(@llvm\.memcpy[^\n]*ptr noundef nonnull align 4 dereferenceable\(52\) getelementptr inbounds nuw \(i8, ptr '
                + re.escape(identity) + r', i64 )52(\), i64 52,)', r'\g<1>104\g<2>'),
            ("wrong-code-offset", names[0], re.escape(code_pointer),
                code_pointer.replace(str(first["code_offset"]), str(first["code_offset"] + 16))),
            ("wrong-material-offset", names[0], re.escape(material_pointer),
                material_pointer.replace(str(first["material_offset"]), str(first["material_offset"] + 16))),
        ))
    else:
        identity_offset = first["creator_index"] * 52
        identity_source = (identity if identity_offset == 0 else
                           f"getelementptr (i8, ptr {identity}, i64 {identity_offset})")
        next_identity = f"getelementptr (i8, ptr {identity}, i64 {identity_offset + 52})"
        mutations.extend((
            ("after-handoff-clobber", names[0], r'call void @llvm\.memcpy[^\n]+i64 96, i1 false\)[^\n]*', clobber),
            ("wrong-material-source", names[0], re.escape(material_offsets), offsets),
            ("swapped-owner-slot", names[0],
                r'(getelementptr inbounds nuw \[2 x %"class\.pyobfuscator::native::BootstrapContextOwner"\], ptr %\d+, i64 0, i64 )0', r'\g<1>1'),
            ("swapped-lease-slot", names[0],
                r'(getelementptr inbounds nuw \[2 x %"class\.pyobfuscator::native::BootstrapContextLease"\], ptr %\d+, i64 0, i64 )0', r'\g<1>1'),
            ("swapped-handoff-slot", names[0],
                r'(getelementptr inbounds nuw \[2 x %"struct\.pyobfuscator::native::demo::PostRole"\], ptr %\d+, i64 0, i64 )0', r'\g<1>1'),
            ("wrong-spec-identity", names[0],
                r'(@llvm\.memcpy[^\n]*ptr align 4 )' + re.escape(identity_source) + r'(, i64 52,)',
                r'\g<1>' + next_identity + r'\g<2>'),
        ))
    with tempfile.TemporaryDirectory(prefix="post-role-flow-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        for label, function, pattern, replacement in mutations:
            path = directory / f"{label}.ll"
            path.write_text(replace_function(original, function, pattern, replacement), encoding="utf-8")
            run([args.opt, "-passes=verify", "-disable-output", path])
            report, output = directory / f"{label}.json", directory / f"{label}.protected.ll"
            failed = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={args.configuration}", f"-pyobf-cff-seed={args.seed}",
                "-pyobf-cff-markers=true", f"-pyobf-cff-requests-input={args.requests}",
                f"-pyobf-cff-report={report}", "-verify-each", "-S", path, "-o", output], succeeds=False)
            if output.exists() or ("post role flow:" not in failed.stderr and
                    "owner creator:" not in failed.stderr):
                raise AssertionError(f"{label} escaped its actual compiler flow gate: {failed.stderr[-400:]}")
    print(f"actual POST role flow and {len(mutations)} LLVM-valid wrong-flow refusals verified")


if __name__ == "__main__":
    main()
