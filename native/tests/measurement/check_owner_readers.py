"""Actual generated owner callbacks for one subject; not a production CFF claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

from check_capture import ROOT
from check_functions import prepare_fixture
from check_reference import WORDS
from code_observation import reference_digest
from code_reference import build_reference
from function_subject import function_subject
from function_inventory import create as inventory
from owner_reader_plan import render_header, render_source
from pe_layout import parse_image
from reference_identity import identity_bytes
from reference_plan import parse_plan

sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import protect, run, verify_image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compiler", "runtime_directory", "build_dir"): parser.add_argument(name, type=Path)
    parser.add_argument("--core", nargs="+", required=True, type=Path)
    parser.add_argument("--backend", nargs="+", required=True, type=Path)
    for name in ("opt", "plugin", "llvm-link", "objdump"): parser.add_argument("--" + name, type=Path)
    parser.add_argument("--profile", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    args = parser.parse_args()
    if any((args.opt, args.plugin, args.llvm_link, args.objdump, args.profile)) and not all(
            (args.opt, args.plugin, args.llvm_link, args.objdump, args.profile)):
        parser.error("protected reader execution needs all matching LLVM tools and its source profile")
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="owner-readers-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        _, fragments, dll = prepare_fixture(args.compiler, directory)
        plan_path, header, source = (directory / name for name in ("plan.json", "owner_readers.hpp", "owner_readers.cpp"))
        plan_path.write_text(json.dumps({"schema_version": 1, "build_seed": "11" * 16, "container": "22" * 16,
            "records": [{"image": "33" * 16, "owner": owner, "subject": 0x931, "kind": 3, "stage": 2, "capacity": 4096,
                "selector": {"symbol": "extent_split", "aliases": ["extent_alias"], "fragments": ["extent_cold"]}}
                for owner in (7, 8, 9)]}), encoding="utf-8")
        plan = parse_plan(plan_path.read_bytes())
        command = [sys.executable, ROOT / "tools/prepare_owner_readers.py", plan_path, header, source]
        run(command)
        if header.read_text() != render_header(plan) or source.read_text() != render_source(plan):
            raise AssertionError("owner CLI differs from the early source contract")
        snapshots = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (plan_path, header, source)}
        run(command)
        if any((path.read_bytes(), path.stat().st_mtime_ns) != before for path, before in snapshots.items()):
            raise AssertionError("unchanged owner source regenerated")
        for output in (1, 2):
            for target in (plan_path, header, source):
                if target == (header, source)[output - 1]: continue
                invalid = list(command); invalid[output + 2] = target
                run(invalid, succeeds=False)
                if any((path.read_bytes(), path.stat().st_mtime_ns) != before for path, before in snapshots.items()):
                    raise AssertionError("refused owner output alias changed an input")
        data = dll.read_bytes(); image = parse_image(data)
        parameters = []
        for record in plan.records:
            identity = record.identity
            subject = function_subject(fragments.read_bytes(), data, image, identity.subject, record.symbol,
                aliases=record.aliases, fragments=record.fragments)
            metadata, package = directory / f"{identity.owner}.meta", directory / f"{identity.owner}.bin"
            metadata.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS) + reference_digest(data, image, subject, identity.owner))
            package.write_bytes(build_reference(data, subject, identity, WORDS)); parameters.extend((metadata, package))
        includes = ["-I", ROOT / "include", "-I", ROOT / "src", "-I", directory]
        hashes = [path for path in args.backend if path.name == "hash.cpp"]
        if len(hashes) != 1: raise AssertionError("owner probe needs its actual CNG backend")
        native = directory / "hash.actual.obj"
        run([args.compiler, "-std=c++17", "-O2", "-fno-lto", *includes, "-Dhash_sha256=hash_sha256_actual", "-c", hashes[0], "-o", native])
        binary = directory / "owners.exe"
        implementation, report = source, None
        client = ROOT / "tests/measurement/owner_creator_client.cpp"
        if args.profile:
            args.optimization = args.profile
            unit = directory / "owner-readers.ll"
            run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
                *includes, source, "-o", unit])
            if "@llvm.global_ctors" in unit.read_text(): raise AssertionError("owner readers introduced dynamic initialization")
            client_unit = directory / "owner-client.ll"
            run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
                *includes, client, "-o", client_unit])
            _, implementation, report = protect(args, directory, "readers", [unit, client_unit], 3 * len(plan.records) + 1)
            implementation = directory / "readers.sections.obj"
            run([args.compiler, "-O0", "-fno-lto", "-ffunction-sections", "-c", directory / "readers.protected.ll", "-o", implementation])
            manifest = directory / "readers.ownership.json"
            manifest.write_bytes(inventory(implementation.read_bytes(), (directory / "readers.protected.ll").read_bytes(), report.read_bytes()))
        run([args.compiler, "-std=c++17", "-O2", *(["-flto=thin"] if args.ipo else ["-fno-lto"]), *includes,
            implementation, *([] if report else [client]), ROOT / "tests/measurement/owner_reader_probe.cpp",
            *args.core, *[path for path in args.backend if path not in hashes], native, "-lbcrypt", "-o", binary])
        if report:
            verify_image([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump, "--owner-object", implementation,
                "--owner-inventory", manifest, "--owner-plan", plan_path], binary, report, directory / "owners.final.json")
            if args.profile == "none":
                from check_owner_reader_refusals import source_refusals, image_refusals
                source_refusals(args, directory, directory / "readers.ll", report, plan)
                image_refusals(args, directory, binary, report, implementation, manifest, plan, plan_path)
                from check_owner_creator_refusals import source_refusals as creator_source_refusals
                from check_owner_creator_refusals import image_refusals as creator_image_refusals
                creator_source_refusals(args, directory, directory / "readers.ll", report)
                creator_image_refusals(directory, binary, report, implementation, manifest, plan)
        print(run([binary, *parameters, dll]).stdout.strip())
        module_a, module_b, lifetime = (directory / name for name in ("reader-a.dll", "reader-b.dll", "lifetime.exe"))
        run([args.compiler, "-std=c++17", "-O2", "-fno-lto", "-shared", *includes, implementation,
            ROOT / "tests/measurement/owner_reader_module.cpp", *args.core, *args.backend, "-lbcrypt", "-o", module_a])
        module_b.write_bytes(module_a.read_bytes())
        if report:
            checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump, "--owner-object", implementation,
                "--owner-inventory", manifest, "--owner-plan", plan_path]
            for module in (module_a, module_b):
                verify_image(checker, module, report, module.with_suffix(".final.json"))
        pins = [path for path in args.backend if path.name == "code_lifetime.cpp"]
        if len(pins) != 1: raise AssertionError("reader lifetime probe needs the actual code pin backend")
        pin_object = directory / "pins.actual.obj"
        run([args.compiler, "-std=c++17", "-O2", "-fno-lto", *includes, "-Dretain_code=retain_code_actual",
            "-c", pins[0], "-o", pin_object])
        run([args.compiler, "-std=c++17", "-O2", *(["-flto=thin"] if args.ipo else ["-fno-lto"]), *includes,
            ROOT / "tests/measurement/owner_reader_lifetime.cpp", *args.core,
            *[path for path in args.backend if path not in pins], pin_object, "-lbcrypt", "-o", lifetime])
        print(run([lifetime, *parameters[:2], dll, module_a, module_b]).stdout.strip())
        for role in ("capture", "codec"):
            rejected = run([lifetime, *parameters[:2], dll, module_a, module_b, "borrow-" + role], succeeds=False)
            if rejected.returncode != 1 or f"{role} module detached before first observation" not in rejected.stderr:
                raise AssertionError("unretained callback handle failed outside the actual early-unload boundary")
        print("borrowed capture and codec handle mutants both fail at actual early DLL detach")
        print("early source SHA", hashlib.sha256(source.read_bytes()).hexdigest())


if __name__ == "__main__": main()
