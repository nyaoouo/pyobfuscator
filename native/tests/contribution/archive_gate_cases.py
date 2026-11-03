"""Real archived-key errors and normal-preserving state-binding erasure."""
import json
import re
import subprocess

from cff_build import run
from archive_gate_pipeline import prepare_archive_gates


def check_archive_image(image, info):
    data = image.read_bytes()
    for selected in (b"A\0B\xffC!\0", bytes.fromhex("00d85a000000"), bytes.fromhex("420000000000f87f")):
        if selected in data:
            raise AssertionError("selected archive source storage survived in the actual image")
    if "contribution_hybrid" in info["owners"] and b"Hy\0\xffb!\0" in data:
        raise AssertionError("selected hybrid archive storage survived in the actual image")
    if any(bytes.fromhex(record["key_hex"]) in data for record in info["bindings"]["records"]):
        raise AssertionError("a full raw archive key survived in the actual image")


def archive_refusals(args, directory, protected, info, claimed, checker, build_image, *, owner="contribution_archive_value"):
    original = protected.read_text()
    keys = {record["id"]: bytes.fromhex(record["key_hex"]) for record in info["bindings"]["records"]}
    # Archive binding descriptors are intentionally erased at finish. Join the existing
    # private source/child map to retained CFF provenance instead of retaining key metadata.
    provenance = {value: number for number, value in re.findall(r'(?m)^!(\d+) = !\{!"([^"\n]+)"\}', original)}
    inventory = info["owners"][owner]
    mapping = next(row for row in info["private_map"]["functions"] if row["function"] == owner)
    targets = []
    identities = set()
    if len(mapping["archive_sources"]) != inventory["acquisitions"]:
        raise AssertionError("archive private source inventory differs from prepared acquisitions")
    for source in mapping["archive_sources"]:
        record = source["acquisition"].split(":", 1)[0]
        for child in source["children"]:
            if child["role"] != "key-word32":
                continue
            identity, component, operand = child["site_id"].rsplit(":", 2)
            if component != "constant-archive" or operand != "0" or child["lane"] >= 8 or identity in identities:
                raise AssertionError("archive erasure did not identify an actual key lane")
            identities.add(identity)
            tag = provenance[identity]
            stores = re.compile(r'(?m)^(  store volatile i32 )%[\w.$-]+(, ptr [^\n]*!pyobf\.cff\.site !' + tag + r'\b[^\n]*)$')
            matches = list(stores.finditer(original))
            if len(matches) != 1:
                raise AssertionError("archive private child does not identify one actual store")
            lane = child["lane"]
            word = int.from_bytes(keys[record][lane * 4:lane * 4 + 4], "little")
            targets.append((stores, word))
    if len(targets) != inventory["lanes"]:
        raise AssertionError("archive erasure did not reach every independent original key lane")
    erased = original
    for stores, word in targets:
        erased, changed = stores.subn(lambda match: match[1] + str(word) + match[2], erased)
        if changed != 1:
            raise AssertionError("archive erasure lost an independent key store")
    source = directory / (owner + "-archive-static-keys.ll")
    source.write_text(erased)
    run([args.opt, "-passes=verify", "-disable-output", source])
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify", "-disable-output", source])
    image = build_image(owner + "-archive-static-keys", source)
    if "gate-normal-completed" not in run([image]).stdout:
        raise AssertionError("removing archive state binding changed normal reference behavior")
    final = directory / (owner + "-archive-static-keys.final.json")
    result = run([*checker, image, claimed, "--output", final], succeeds=False)
    if "lost state-dependent archive keys: " + owner not in result.stderr or final.exists():
        raise AssertionError("static archive keys borrowed another component's final evidence")

    # Preserve the complete source/query path; corrupt one real key on cold first use.
    stores, word = targets[0]
    changed, count = stores.subn(lambda match: match[1] + str(word ^ 1) + match[2], original, count=1)
    if count != 1:
        raise AssertionError("archive wrong-key mutation did not reach actual emitted work")
    source = directory / (owner + "-archive-wrong-key.ll")
    source.write_text(changed)
    run([args.opt, "-passes=verify", "-disable-output", source])
    image = build_image(owner + "-archive-wrong-key", source)
    result = subprocess.run([image], capture_output=True, text=True, timeout=5)
    if result.returncode == 0 or "gate-enter" not in result.stdout or "gate-normal-completed" in result.stdout:
        raise AssertionError("wrong actual archive key reached the data consumer's successful result")
    return 2 + archive_loss_refusals(args, directory, hybrid=owner == "contribution_hybrid")


def archive_loss_refusals(args, directory, *, hybrid=False):
    directory = directory / ("archive-loss-hybrid" if hybrid else "archive-loss")
    directory.mkdir()
    source = directory / "source.ll"
    source.write_text('''target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
target triple = "x86_64-w64-windows-gnu"
declare void @pyobf_native_contribution_site_v1(ptr, i32) nounwind
define i32 @contribution_archive_value(ptr %lease, i32 %value) {
entry:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 501)
  %dead = add i32 %value, 7
  ret i32 %value
}
''')
    recipe, requests, requested, optimized, private = [directory / name for name in (
        "recipe.json", "requests.json", "requested.ll", "optimized.ll", "private.json")]
    config = {"schema_version": 1, "functions": {"contribution_archive_value": {"components": {
        "runtime-contribution": "required", "constant-archive": "required"}}}}
    if hybrid:
        config["functions"]["contribution_archive_value"]["coverage"] = "hybrid-eh"
        text = source.read_text().replace("define i32 @contribution_archive_value(ptr %lease, i32 %value) {",
            "declare i32 @__gxx_personality_seh0(...)\ndeclare void @may_throw()\n"
            "declare void @cleanup_observer(ptr) nounwind\n"
            "define i32 @contribution_archive_value(ptr %lease, i32 %value) personality ptr @__gxx_personality_seh0 {")
        source.write_text(text.replace("  ret i32 %value", "  invoke void @may_throw() to label %normal unwind label %pad\n"
            "normal:\n  ret i32 %value\npad:\n  %exception = landingpad { ptr, i32 } cleanup\n"
            "  %pointer = extractvalue { ptr, i32 } %exception, 0\n  call void @cleanup_observer(ptr %pointer)\n"
            "  resume { ptr, i32 } %exception"))
    recipe.write_text(json.dumps(config))
    private.write_text(json.dumps({"schema_version": 1, "provider": "owned-context-v1", "routing_tag": 7,
        "domain": 11, "source": 17, "private_words": list(range(1, 9)), "owners": {"contribution_archive_value": 35}}))
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={recipe}", "-verify-each"]
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}", "-S", source, "-o", requested])
    run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", optimized])
    source, requests, empty = prepare_archive_gates(args, directory, optimized, recipe, requests)
    if empty["plan"]["records"] or empty["bindings"]["records"]:
        raise AssertionError("optimized-away data or closed point ID entered the empty archive")
    for required in (True, False):
        config["functions"]["contribution_archive_value"]["components"]["constant-archive"] = "required" if required else "optional"
        recipe.write_text(json.dumps(config))
        report = directory / ("strict.json" if required else "optional.json")
        run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
            f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
            "-disable-output", source], succeeds=not required)
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "contribution_archive_value")
        if required:
            if "required archive source request is absent or incomplete" not in row.get("reason", ""):
                raise AssertionError("lost required archive source failed outside its original request boundary")
        else:
            component = next(item for item in row["components"] if item["component"] == "constant-archive")
            inventory = row["archive_sources"]
            if (row["status"] != "transformed" or component["applied"] != 0 or inventory["requested"] != 1 or
                    inventory["applied"] != 0 or inventory["acquisitions"] != 0):
                raise AssertionError("empty optional archive earned false source/acquisition coverage")
    return 2
