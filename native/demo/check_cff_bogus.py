"""Exercise safe clone/synthesis decoys, allocation, actual origins and linked retention."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import SOURCE_IR, HARNESS, HELPER, run


UNSAFE = r'''
define i32 @unsafe(ptr %p, i32 %x) {
entry:
  %value = load i32, ptr %p
  %sum = add i32 %value, %x
  br label %next
next:
  %shift = shl i32 %sum, %x
  br label %done
done:
  ret i32 %shift
}
define i32 @poison_donor(i32 %x) {
entry:
  %value = add i32 poison, %x
  br label %next
next:
  ret i32 %value
}
define i32 @flags(i32 %x) {
entry:
  %a = add nsw nuw i32 %x, 3
  %b = mul nsw i32 %a, 7
  br label %next
next:
  ret i32 %b
}
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output = directory / "source.ll", directory / "output.ll"
        report, private = directory / "coverage.json", directory / "private.json"
        config_file = directory / "recipe.json"
        helper, harness = directory / "helper.cpp", directory / "harness.cpp"
        source.write_text(SOURCE_IR + UNSAFE, encoding="utf-8")
        helper.write_text(HELPER, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        baseline = directory / "baseline.exe"
        run([str(args.compiler), str(source), str(helper), str(harness), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout

        def transform(functions: dict, seed: int = 1, *, succeeds: bool = True):
            config_file.write_text(json.dumps({"schema_version": 1, "functions": functions}), encoding="utf-8")
            output.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                          f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={report}",
                          f"-pyobf-cff-private-map={private}", f"-pyobf-cff-seed={seed}",
                          "-verify-each", "-S", str(source), "-o", str(output)], succeeds=succeeds)
            if not succeeds:
                if output.exists(): raise AssertionError("failed bogus recipe emitted an artifact")
                return result
            return {row["function"]: row for row in json.loads(report.read_text())["functions"]}

        def entry(features: tuple[str, ...], **budgets) -> dict:
            return {"components": {name: "required" for name in features}, "budgets": {
                "max_bogus_blocks": 4, "max_clone_instructions": 3, "synthesis_rounds": 3, **budgets}}

        profiles = (("bogus-clones",), ("bogus-synthesis",), ("bogus-clones", "bogus-synthesis"),
                    ("bogus-clones", "bogus-synthesis", "opaque-choices", "reachable-junk"))
        retained = None
        retained_ir = None
        for seed in (1, 19, 777):
            for index, features in enumerate(profiles):
                config = {name: entry(features) for name in ("heavy", "recursive", "callback_case", "flags")}
                # Exercise all D1 structural components before fake structure and final state binding.
                if index == 3:
                    config["heavy"]["components"].update({
                        name: "optional" for name in ("split-blocks", "common-exit", "deduplicate-blocks",
                                                       "integer-literals", "internal-calls", "decoy-transitions")})
                    config["heavy"]["budgets"]["max_block_instructions"] = 4
                rows = transform(config, seed)
                for name in config:
                    row = rows[name]
                    totals = row["site_totals"]
                    fake = totals["bogus_clone_blocks"] + totals["bogus_synthesis_blocks"]
                    if row["status"] != "transformed" or not 1 <= fake <= 4 or totals["decoy_blocks"] != fake:
                        raise AssertionError(f"bogus budget/origin differs: {row}")
                    if totals["body_roles"].get("decoy") != fake or totals["transition_roles"].get("decoy") != fake:
                        raise AssertionError("fake structure is not separately classified")
                    if totals["oracle_gates"] != 0 or totals["transition_roles"].get("routing", 0) < fake:
                        raise AssertionError("fake inbound edges borrowed real/oracle coverage")
                    for component in row["components"]:
                        if component["component"] not in ("bogus-clones", "bogus-synthesis") or not component["applied"]:
                            continue
                        if component["applied_roles"] != {"routing": component["applied"]}:
                            raise AssertionError("fake guard does not have a distinct routing site")
                        if any(site["status"] == "eligible" for site in component["sites"]):
                            raise AssertionError("required fake site left unbound")
                ir = output.read_text()
                if re.search(r"pyobf\.clone\.value[^\n]* = (?:add|mul|sub) (?:nsw|nuw)", ir):
                    raise AssertionError("clone copied poison-generating donor flags")
                private_rows = json.loads(private.read_text())["functions"]
                donors = [site for row in private_rows for site in row["sites"] if site.get("donor_provenance")]
                if "bogus-clones" in features and not donors:
                    raise AssertionError("clone donor provenance was not retained privately")
                binary = directory / f"protected-{seed}-{index}.exe"
                run([str(args.compiler), str(output), str(helper), str(harness), "-o", str(binary)])
                if run([str(binary)]).stdout != expected:
                    raise AssertionError("fake structure changed memory/loop/recursion/callback behavior")
                image = directory / f"protected-{seed}-{index}.dll"
                run([str(args.compiler), "-shared", str(output), str(helper), "-o", str(image)])
                run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])
                if seed == 1 and index == 2:
                    retained = report.read_text()
                    retained_ir = ir

        # Retaining only inbound guards must not count discarded fake computations as present.
        erased_ir, erased_count = re.subn(
            r"store i32 %pyobf\.junk\.mix(?:\.?\d+)?, ptr %pyobf\.state",
            "store i32 0, ptr %pyobf.state", retained_ir)
        if erased_count == 0: raise AssertionError("fake work has no state consumption")
        output.write_text(erased_ir, encoding="utf-8")
        erased_image = directory / "erased-work.dll"
        claimed = directory / "claimed.json"
        claimed.write_text(retained, encoding="utf-8")
        run([str(args.compiler), "-shared", str(output), str(helper), "-o", str(erased_image)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump),
                      str(erased_image), str(claimed)], succeeds=False)
        if "coefficients" not in result.stderr:
            raise AssertionError(f"fake-work erasure failed for unrelated reason: {result.stderr}")

        for name in ("unsafe", "poison_donor", "tail"):
            transform({name: entry(("bogus-clones",))}, succeeds=False)
            rejected = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == name)
            if rejected["status"] != "unsupported" or "donor" not in rejected["reason"]:
                raise AssertionError(f"unsafe donor rejection differs: {rejected}")

        # Optional unavailable clones become explicit synthesis, never claimed clone coverage.
        fallback = entry(("bogus-synthesis",), min_blocks=7)
        fallback["components"]["bogus-clones"] = "optional"
        tiny = transform({"tiny": fallback})["tiny"]
        totals = tiny["site_totals"]
        synthesis = next(item for item in tiny["components"] if item["component"] == "bogus-synthesis")
        clones = next(item for item in tiny["components"] if item["component"] == "bogus-clones")
        if (totals["bogus_clone_blocks"] or totals["bogus_synthesis_blocks"] != 4 or clones["applied"] or
                synthesis["preparation"]["fallback_blocks"] != 2 or tiny["coverage_kind"] != "shape-only"):
            raise AssertionError("optional clone fallback inflated clone/real coverage")

        for percent, required in ((0, "bogus-clones"), (100, "bogus-synthesis")):
            transform({"heavy": entry(("bogus-clones", "bogus-synthesis"), clone_percent=percent)},
                      succeeds=False)
            rejected = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "heavy")
            if f"{required} has zero eligible" not in rejected["reason"]:
                raise AssertionError("zero-quota required provider was silently credited")
        for budget in ({"clone_percent": 101}, {"max_clone_instructions": 65}, {"synthesis_rounds": 9},
                       {"max_body_blocks": 4}):
            transform({"heavy": entry(("bogus-synthesis",), **budget)}, succeeds=False)

        # Removing whole fake bodies also removes their required flattened transitions.
        claimed.write_text(retained, encoding="utf-8")
        transform({name: {} for name in ("heavy", "recursive", "callback_case", "flags")})
        absent = directory / "absent.dll"
        run([str(args.compiler), "-shared", str(output), str(helper), "-o", str(absent)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(absent), str(claimed)],
                     succeeds=False)
        if not re.search(r"lost (opaque transition products|bogus .* coefficients|the expected relative-tree shape)", result.stderr):
            raise AssertionError(f"fake erasure failed for unrelated reason: {result.stderr}")


if __name__ == "__main__":
    main()
