"""Original cuts survive earlier typed frame expansion and relocation."""
import json
import re
import sys


def check_retained_split_requests(args, directory, source_ir, harness, expected, run):
    source, requested, requests, configuration = [directory / ("retained-cuts" + suffix)
        for suffix in (".ll", ".requested.ll", ".requests.json", ".json")]
    config = {"schema_version": 1, "functions": {"heavy": {
        "components": {"split-blocks": "required", "call-frames": "required"},
        "budgets": {"max_block_instructions": 4, "max_body_blocks": 100}}}}
    plugin = [str(args.opt), f"-load-pass-plugin={args.plugin}"]
    for label, anchor, before, argument in (
            ("shifted", "%old = atomicrmw", "  store volatile", "a"),
            ("preexpanded", "%old = atomicrmw", "  store volatile", "a"),
            ("relocated", "%split.identity = call", "  %c = add", "b")):
        text = 'target datalayout = "e-m:w-p:64:64-i64:64-n8:16:32:64-S128"\n' + source_ir
        if label != "relocated": text = text.replace("  %b = mul i32 %a", "  %b = mul i32 %split.identity")
        else: text = text.replace("  %c = add i32 %b", "  %c = add i32 %split.identity")
        point = text.index(before)
        text = text[:point] + f"  %split.identity = call i32 @split_identity(i32 %{argument})\n" + text[point:]
        text += "\ndefine i32 @split_identity(i32 %value) {\nentry:\n  ret i32 %value\n}\n"
        source.write_text(text); configuration.write_text(json.dumps(config))
        run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-config={configuration}",
            f"-pyobf-cff-requests-output={requests}", "-verify-each", "-S", str(source), "-o", str(requested)])
        original = requested.read_text()
        marker = re.search(r"(?m)^\s+" + re.escape(anchor) + r"[^\n]*!pyobf\.cff\.site !(\d+)", original)[1]
        identity = re.search(r"(?m)^!" + marker + r' = !\{!"([^"]+)"\}', original)[1]
        if label == "preexpanded":
            original = original.replace("  store volatile i32 %a,", "  store volatile i32 0, ptr @split_scratch\n  store volatile i32 %a,", 1)
            requested.write_text(original + "\n@split_scratch = private global i32 0\n")
        output, report = [directory / ("retained-" + label + suffix) for suffix in (".out.ll", ".report.json")]
        command = [*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-config={configuration}",
            f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-report={report}", "-verify-each", "-S", str(requested), "-o", str(output)]
        try: run(command)
        except AssertionError:
            if report.exists():
                failures = [(row["function"], row.get("reason")) for row in json.loads(report.read_text())["functions"]
                    if row["selected"] and row["status"] != "transformed"]
                raise AssertionError(f"retained split {label} failed: {failures}") from None
            raise
        owner = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "heavy")
        component = next(row for row in owner["components"] if row["component"] == "split-blocks")
        cut = next(row for row in component["sites"] if row["id"] == identity + ":split-blocks:0")
        if component["unsupported"] or cut["status"] != ("relocated" if label == "relocated" else "applied"):
            raise AssertionError("original cut disappeared during earlier frame normalization")
        if label == "relocated" and not any(row["id"] == cut["replacement"] and row["status"] == "applied" for row in component["sites"]):
            raise AssertionError("relocated original call cut has no applied frame-store boundary")
        binary = directory / ("retained-" + label + ".exe")
        run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
        if run([str(binary)]).stdout != expected:
            raise AssertionError("retained split requests changed SSA/memory/loop results")
        image = directory / ("retained-" + label + ".dll")
        run([str(args.compiler), "-shared", str(output), "-o", str(image)])
        run([sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])
    print("original cuts retained across pre-inventory insertion, typed frame expansion and call relocation")
