"""Exercise the early/late mixed POST private-input boundary."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from payload_binding import OWNER, WRAPPER  # noqa: E402
from post_mixed_binding import PROFILE, mixed_private_reference, validate_mixed_bound_child  # noqa: E402
from post_reference_plan import create as create_post_plan  # noqa: E402
from release_material import material_fold  # noqa: E402
from release_plan import bind_material, render_header  # noqa: E402


def refusal(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError("malformed mixed POST input was accepted")


def main():
    material = {"schema_version": 1, "seed": 11,
        "events": {role: {"tag": index * 2 + 21, "word": index * 2 + 22}
                   for index, role in enumerate(("environment", "support", "release"))}}
    recipe = {"strategy": "relative-tree", "coverage": "whole",
              "contribution": {"selection": "original-edges", "minimum_edges": 3,
                               "maximum_edges": 8, "minimum_percent": 100},
              "components": [{"component": "runtime-contribution", "requirement": "required"}]}
    plan = {"schema_version": 2, "profile": PROFILE, "input_ir_encoding": "llvm-module-print-v1",
            "input_ir_sha256": "1" * 64,
            "owners": [{"owner": owner, "recipe": recipe,
                        "edges": [{"id": f"{owner}:edge:{index}", "label": base + index,
                                   "successor_index": index % 2} for index in range(count)]}
                       for owner, base, count in ((OWNER, 101, 8), (WRAPPER, 201, 3))]}
    scoped = bytes(range(32))
    raw = json.dumps(plan).encode()
    with TemporaryDirectory(prefix="post-mixed-binding-", dir=Path.cwd()) as directory:
        root = Path(directory)
        material_file = root / "release.json"
        config_file = root / "demo_config.hpp"
        scope_file = root / "scope.bin"
        plan_file = root / "plan.json"
        recipe_file = root / "recipe.json"
        private_file = root / "private.json"
        profile_file = root / "post_profile.hpp"
        sites_file = root / "post_mixed_sites.hpp"
        material_file.write_text(json.dumps(material), encoding="ascii")
        config_file.write_text("#define PYOBF_DEMO_ENV_OPERATION_ID 123u\n", encoding="ascii")
        scope_file.write_bytes(scoped)
        plan_file.write_bytes(raw)
        base = [sys.executable, str(TOOLS / "prepare_payload_binding.py"),
                str(material_file), str(config_file), str(recipe_file), str(private_file),
                "--scope-material", str(scope_file), "--post-profile", str(profile_file), "--mixed"]
        subprocess.run(base + ["--phase", "early"], check=True, capture_output=True)
        if private_file.exists() or not profile_file.exists():
            raise AssertionError("early mixed recipe generated late private input")
        generated_recipe = json.loads(recipe_file.read_text(encoding="ascii"))
        for owner in (OWNER, WRAPPER):
            if generated_recipe["functions"][owner]["contribution"] != recipe["contribution"]:
                raise AssertionError("mixed recipe lost complete original-edge budget")
        subprocess.run(base + ["--phase", "late", "--mixed-plan", str(plan_file),
                               "--mixed-header", str(sites_file)],
                       check=True, capture_output=True)
        private = json.loads(private_file.read_text(encoding="ascii"))
        post_plan = create_post_plan(material_file.read_bytes(), "pyobf_native_demo_outer_unfinalized",
                                     private_file.read_bytes(), scoped, pre_release=False, mixed_plan=raw)
        if len(post_plan.records) != 2:
            raise AssertionError("mixed POST reference plan lost either exact role")
        if (private["root_scheme"] != "provider-split-v1" or
                private["private_words"] != list(material_fold(material)) or
                private["measured_private_words"] != list(struct.unpack("<8I", scoped)) or
                set(private["bindings"]) != {OWNER, WRAPPER}):
            raise AssertionError("late private roots or owner inventory differ from inputs")
        rendered_sites = sites_file.read_text(encoding="ascii")
        if (rendered_sites.count("{" + str(private["owners"][OWNER]) + "u, 101u,") != 1 or
                rendered_sites.count("{" + str(private["owners"][WRAPPER]) + "u, 201u,") != 1):
            raise AssertionError("parent site table differs from both private owner identities")
        for owner, base_label, count in ((OWNER, 101, 8), (WRAPPER, 201, 3)):
            sites = private["bindings"][owner]["sites"]
            if set(sites) != {str(base_label + index) for index in range(count)}:
                raise AssertionError("late private sites differ from the frozen plan")
            subsets = [tuple(site["sources"][:-1]) for site in sites.values()]
            if len(set(subsets)) != count or any(not subset for subset in subsets) or any(
                    site["sources"][-1] != "post-owner-code" for site in sites.values()):
                raise AssertionError("planned edges lack distinct owned subsets and measured evidence")
        bad = copy.deepcopy(plan)
        bad["owners"].reverse()
        refusal(lambda: mixed_private_reference(material, 123, scoped, json.dumps(bad).encode()))
        bad = copy.deepcopy(plan)
        bad["owners"][1]["edges"][0]["label"] = 101
        refusal(lambda: mixed_private_reference(material, 123, scoped, json.dumps(bad).encode()))
        bad = copy.deepcopy(plan)
        bad["owners"][0]["recipe"]["contribution"]["minimum_percent"] = 99
        refusal(lambda: mixed_private_reference(material, 123, scoped, json.dumps(bad).encode()))
        bad = copy.deepcopy(plan)
        bad["profile"] = "schema4-original-edges-bounded-v2"
        refusal(lambda: mixed_private_reference(material, 123, scoped, json.dumps(bad).encode()))
        bad_private = copy.deepcopy(private)
        bad_private["private_words"][0] ^= 1
        refusal(lambda: create_post_plan(material_file.read_bytes(), "pyobf_native_demo_outer_unfinalized",
                                        json.dumps(bad_private).encode(), scoped, pre_release=False, mixed_plan=raw))
        bad_private = copy.deepcopy(private)
        bad_private["bindings"][OWNER]["sites"]["101"]["sources"] = ["post-owner-code"]
        refusal(lambda: create_post_plan(material_file.read_bytes(), "pyobf_native_demo_outer_unfinalized",
                                        json.dumps(bad_private).encode(), scoped, pre_release=False, mixed_plan=raw))
        refusal(lambda: create_post_plan(material_file.read_bytes(), "pyobf_native_demo_outer_unfinalized",
                                        private_file.read_bytes(), scoped, pre_release=False,
                                        mixed_plan=json.dumps(bad).encode()))
        refusal(lambda: mixed_private_reference(material, 123, struct.pack("<8I", *material_fold(material)), raw))
        image = b"post-mixed-child-fixture"
        final = {"strategy": "relative-tree", "verification_scope": "function-shape-and-component-presence",
                 "image_sha256": hashlib.sha256(image).hexdigest(), "functions": []}
        for owner, _, count in ((OWNER, 101, 8), (WRAPPER, 201, 3)):
            final["functions"].append({"function": owner, "selected": True,
                "status": "final-binary-verified", "final_binary_verified": True,
                "runtime_contribution": {"scheme_version": 4, "provider": "source-mixed-v1",
                    "private_input_sha256": hashlib.sha256(private_file.read_bytes()).hexdigest(),
                    "final_query_presence_verified": True, "original_real_edge_density_verified": True,
                    "original_edge_machine": {"verified": True,
                        "plan_sha256": hashlib.sha256(raw).hexdigest(),
                        "planned_edges": count, "selected_edges": count, "bound_edges": count}}})
        final_bytes = (json.dumps(final, sort_keys=True) + "\n").encode()
        release = bind_material(material, image, final_bytes)
        def validate(report):
            return validate_mixed_bound_child(release, private_file.read_bytes(),
                (json.dumps(report, sort_keys=True) + "\n").encode(),
                material_bytes=material_file.read_bytes(), scoped_material=scoped,
                mixed_plan_bytes=raw)
        if set(validate(final)["owners"]) != {OWNER, WRAPPER}:
            raise AssertionError("mixed package gate lost a linked owner")
        changed = copy.deepcopy(final)
        changed["functions"][0]["runtime_contribution"]["original_edge_machine"]["bound_edges"] -= 1
        refusal(lambda: validate(changed))
        changed = copy.deepcopy(final)
        changed["functions"][1]["runtime_contribution"]["original_edge_machine"]["plan_sha256"] = "0" * 64
        refusal(lambda: validate(changed))
        changed = copy.deepcopy(final)
        changed["functions"].pop()
        refusal(lambda: validate(changed))
        image_file = root / "child.dll"
        final_file = root / "child.final.json"
        release_file = root / "release-plan.json"
        events_file = root / "path_events.hpp"
        package_file = root / "payload_blob.hpp"
        record_file = root / "release.record"
        image_file.write_bytes(image)
        final_file.write_bytes(final_bytes)
        release_file.write_text(json.dumps(release), encoding="ascii")
        events_file.write_text(render_header(release), encoding="ascii")
        pack = [sys.executable, str(Path(__file__).with_name("pack_payload.py")),
            str(image_file), str(package_file), str(record_file), str(release_file),
            str(events_file), str(final_file), "--contribution-input", str(private_file),
            "--binding-provider", "measured-scope-v1", "--scope-material", str(scope_file),
            "--mixed-plan", str(plan_file), "--release-material", str(material_file)]
        subprocess.run(pack, check=True, capture_output=True)
        if not package_file.read_bytes() or not record_file.read_bytes():
            raise AssertionError("mixed POST packaging did not emit a sealed child")
        changed_private = copy.deepcopy(private)
        changed_private["private_words"][0] ^= 1
        private_file.write_text(json.dumps(changed_private), encoding="ascii")
        if subprocess.run(pack, capture_output=True).returncode == 0:
            raise AssertionError("mixed POST packaging accepted a substituted release root")
        private_file.write_text(json.dumps(private, indent=2, sort_keys=True) + "\n", encoding="ascii")
        if subprocess.run(base + ["--phase", "late"], capture_output=True).returncode == 0:
            raise AssertionError("late phase accepted a missing frozen plan")
        if subprocess.run(base + ["--phase", "early", "--mixed-plan", str(plan_file),
                                  "--mixed-header", str(sites_file)],
                          capture_output=True).returncode == 0:
            raise AssertionError("early phase consumed a late frozen plan")
    print("mixed POST early/late roots, sites, package admission and plan/root refusals passed")


if __name__ == "__main__":
    main()
