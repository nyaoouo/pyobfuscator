"""Equivalent void completions retain separate compiler-owned source identities."""
import json

from cff_build import run


SOURCE = '''target triple = "x86_64-w64-windows-gnu"
target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
declare i32 @__gxx_personality_seh0(...)
declare void @side()
declare void @pyobf_native_contribution_site_v1(ptr, i32) nounwind
define i32 @void_owner(ptr %lease, i1 %choose) personality ptr @__gxx_personality_seh0 {
entry:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 101) nounwind
  br i1 %choose, label %left, label %right
left:
  invoke void @side() to label %join unwind label %pad
right:
  invoke void @side() to label %join unwind label %pad
join:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 202) nounwind
  ret i32 0
pad:
  %exception = landingpad {ptr, i32} cleanup
  resume {ptr, i32} %exception
}
'''


def void_completion_cases(args, directory):
    private = directory / "void-completion.private.json"
    private.write_text(json.dumps({"schema_version": 1, "provider": "owned-context-v1", "routing_tag": 7,
        "domain": 11, "source": 17, "private_words": list(range(1, 9)), "owners": {"void_owner": 13}}))
    native = []
    for mode in ("off", "bounded", "optional", "required"):
        source, configuration, output, report = [directory / ("void-completion-" + mode + suffix)
            for suffix in (".ll", ".json", ".out.ll", ".report.json")]
        text = SOURCE
        if mode == "required":
            # A genuine original duplicate prevents zero-eligibility rejection from
            # hiding the required generated-completion ownership refusal.
            text = text.replace("entry:\n", "entry:\n  %saved = alloca i32\n  %seed = zext i1 %choose to i32\n", 1)
            text = text.replace("  br i1 %choose, label %left, label %right", '''  br i1 %choose, label %original.a, label %original.b
original.a:
  %a = add i32 %seed, 7
  store i32 %a, ptr %saved
  br label %launch
original.b:
  %b = add i32 %seed, 7
  store i32 %b, ptr %saved
  br label %launch
launch:
  br i1 %choose, label %left, label %right''', 1)
            text = text.replace("  ret i32 0", "  %value = load i32, ptr %saved\n  ret i32 %value", 1)
        source.write_text(text)
        configuration.write_text(json.dumps({"schema_version": 1, "functions": {"void_owner": {
            "coverage": "hybrid-eh", "components": {"runtime-contribution": "required",
                "external-calls": "required", "deduplicate-blocks": "optional" if mode == "bounded" else mode},
            **({"budgets": {"max_dedup_comparisons": 1}} if mode == "bounded" else {}),
            "contribution": {"selection": "original-edges"}}}}))
        run([args.opt, "-passes=verify", "-disable-output", source])
        result = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
            f"-pyobf-cff-config={configuration}", f"-pyobf-cff-contribution-input={private}",
            f"-pyobf-cff-report={report}", "-verify-each", "-S", source, "-o", output], succeeds=mode != "required")
        rows = json.loads(report.read_text())["functions"]
        owner = next(row for row in rows if row["function"] == "void_owner")
        component = next(row for row in owner["components"] if row["component"] == "deduplicate-blocks")
        if mode == "required":
            if (output.exists() and output.stat().st_size) or component["unsupported"] < 1 or not any(
                    "registered framed completion identities" in site.get("reason", "") for site in component["sites"]):
                raise AssertionError("required void-completion refusal failed outside its private owner boundary: " + result.stderr[:200])
            continue
        edges = owner["runtime_contribution"]["original_edges"]
        if (owner["status"] != "transformed" or any(row["selected"] and row["status"] != "transformed" for row in rows) or
                tuple(edges[field] for field in ("original_edges", "selected_edges", "bound_edges", "physical_selected_edges",
                    "coalesced_selected_edges", "explicit_points", "excluded_unwind_edges")) != (4, 4, 4, 4, 0, 2, 2) or
                component["applied"] != 0 or (component["unsupported"] < 1 if mode == "bounded" else
                    component["unsupported"] != int(mode == "optional"))):
            raise AssertionError("void completion skip changed independent original inventory or optional coverage")
        run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify", "-disable-output", output])
        obj = directory / ("void-completion-" + mode + ".obj")
        run([args.compiler, "-c", output, "-o", obj])
        code = run([args.objdump, "-dr", obj]).stdout
        readobj = args.objdump.with_name("llvm-readobj" + args.objdump.suffix)
        unwind = run([readobj, "--unwind", "--relocations", obj]).stdout
        # OFF uses earlier gateway placement. Compare native output only against
        # a no-work budget refusal with the same deferred placement and seed.
        if mode != "off":
            native.append((code[code.index("Disassembly of section"):], unwind[unwind.index("Format:"):]))
    if native[0] != native[1]:
        raise AssertionError("optional private-completion skip differs from its deferred no-work native reference")
    print("void completion off/bounded/optional compile; deferred code/relocations/unwind agree; required private-owner merge refused")
