"""Exercise the actual POST child role/Scope/site proof and valid-IR refusals."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile


def run(command, succeeds=True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=35)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected POST child checker result: {result.stderr[:700]}")
    return result


def function(text, name):
    match = re.search(rf"(?m)^define [^\n]*@{re.escape(name)}\([^\n]*\) [^\n]*\{{\n.*?^\}}", text, re.S | re.M)
    if match is None: raise AssertionError(f"missing actual POST child definition: {name}")
    return match


def change_function(text, name, pattern, replacement):
    match = function(text, name)
    changed, count = re.subn(pattern, replacement, match.group(), count=1)
    if count != 1: raise AssertionError(f"POST child mutation anchor changed: {name}")
    return text[:match.start()] + changed + text[match.end():]


def reverse_validation_branch(match):
    return match[1] + match[4] + match[3] + match[2]


def main():
    parser = argparse.ArgumentParser()
    for name in ("opt", "plugin", "source", "protected", "report", "directory"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    proof = report.get("post_child_flow")
    expected = [(0, "pyobf_demo_protection_wrapper", 702), (1, "pyobf_demo_bound_compute", 701)]
    if (type(proof) is not dict or set(proof) != {"schema_version", "scheme", "roles"} or
            proof["schema_version"] != 1 or proof["scheme"] != "post-scope-flow-v1" or
            type(proof["roles"]) is not list or len(proof["roles"]) != 2):
        raise AssertionError("actual child compiler report lacks exact POST flow inventory")
    for row, (role, consumer, site) in zip(proof["roles"], expected):
        if (type(row) is not dict or row != {"role": role, "consumer": consumer, "site": site,
                "role_to_scope_verified": True, "scope_forwarding_verified": True,
                "site_scope_binding_verified": True}):
            raise AssertionError("actual child compiler report misstates a role/site path")
    def verify(path, *, transformed, succeeds=True):
        pass_name = "pyobf-native-post-child-verify" if transformed else "pyobf-native-post-child-source-verify"
        return run([args.opt, f"-load-pass-plugin={args.plugin}", f"-passes={pass_name}",
            "-disable-output", path], succeeds)
    verify(args.source, transformed=False)
    verify(args.protected, transformed=True)
    source = args.source.read_text()
    protected = args.protected.read_text()
    mutations = [
        ("role-slot", change_function(source, "pyobf_demo_post_payload",
            r'(getelementptr inbounds \[2 x %"struct\.pyobfuscator::native::demo::PostRole"\], ptr %\d+, i64 0, i64 )1',
            r'\g<1>0'), False, "Scope mixes post role"),
        ("missing-check", change_function(source, "pyobf_demo_post_payload",
            r'(?m)^  call void @_ZNK12pyobfuscator6native11measurement8observer8Snapshot5checkEv\([^\n]*\n',
            ""), False, "Scope mixes post role"),
        ("first-check-bypass", change_function(source, "pyobf_demo_post_payload",
            r'(icmp ne i32 %\d+, 0[^\n]*\n  br i1 %\d+, label )(%\d+)(, label )(%\d+)',
            reverse_validation_branch), False, "valid post snapshots cannot reach their consumer"),
        ("second-check-bypass", change_function(source, "pyobf_demo_post_payload",
            r'(phi i1 \[ true, %\d+ \], \[ )%\d+(, %\d+ \])',
            r'\g<1>false\g<2>'), False, "post snapshot validation does not gate Scope"),
        ("wrong-fold", change_function(source, "pyobf_demo_post_payload",
            r'(getelementptr inbounds nuw %"struct\.pyobfuscator::native::demo::PostHandoff", ptr %\d+, i32 0, i32 )2',
            r'\g<1>1'), False, "Scope mixes post role"),
        ("site-701", change_function(protected, "pyobf_demo_bound_compute",
            r'(@pyobf_native_measured_contribution_word_v1\([^\n]*i32 )701(, i32 )',
            r'\g<1>703\g<2>'), True, "post marker site"),
        ("compute-scope", change_function(protected, "pyobf_demo_protection_wrapper",
            r'(@pyobf_demo_bound_compute\(ptr[^,\n]* )%\d+(, i32 )',
            r'\g<1>%0\g<2>'), True, "compute received the wrong role Scope"),
    ]
    with tempfile.TemporaryDirectory(prefix="post-child-flow-", dir=args.directory) as temporary:
        for name, text, transformed, reason in mutations:
            path = Path(temporary) / (name + ".ll")
            path.write_text(text)
            run([args.opt, "-passes=verify", "-disable-output", path])
            rejected = verify(path, transformed=transformed, succeeds=False)
            if reason not in rejected.stderr:
                raise AssertionError(f"POST child {name} rejected for another reason: {rejected.stderr[:700]}")
    print("actual POST child role/Scope/site compiler flow and valid-IR refusals verified")


if __name__ == "__main__":
    main()
