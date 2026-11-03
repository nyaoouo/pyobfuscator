"""One per-build dependency chain: late data refresh cannot feed back into code."""
import hashlib
import json
import os
from pathlib import Path
import time

from finalize_measured_release import verify
from post_subjects import artifact_paths, ownership_paths


def dependency_case(args, plan, material, draft, run, *, verifier=verify):
    paths = [args.raw_image, args.material, args.draft, args.reference_object, args.record_object,
        args.reference_directory / "reference_slots.hpp", args.reference_directory / "reference_slots.cpp",
        args.build_dir / "path_events_generated.hpp", args.build_dir / "payload_blob.hpp",
        args.build_dir / "libpyobf_native_demo_inner.dll", args.build_dir / "release-plan.private.json"]
    if args.object: paths.append(args.object)
    if args.coverage: paths.append(args.coverage)
    paths.extend((args.reference_directory / "owner_readers.hpp", args.reference_directory / "owner_readers.cpp"))
    if args.post_input:
        paths.extend(artifact_paths(args, plan).values())
        paths.extend(path for pair in ownership_paths(args, plan).values() for path in pair)
        if args.post_subjects: paths.append(args.post_subjects)
    def snapshot(): return {path: (hashlib.sha256(path.read_bytes()).digest(), path.stat().st_mtime_ns) for path in paths}
    command = [args.cmake, "--build", args.build_dir.parent, "--target", args.dependency_target, "-j", "2"]
    for dependency in (args.plan, Path(__file__).resolve().parents[1] / "tools/measured_scope.py"):
        before, selection, stat = snapshot(), dependency.read_bytes(), dependency.stat()
        original_final = args.image.read_bytes()
        try:
            os.utime(dependency, ns=(stat.st_atime_ns, max(time.time_ns(), stat.st_mtime_ns + 10000000)))
            output = run(command).stdout
            if snapshot() != before or dependency.read_bytes() != selection:
                raise AssertionError("late selection/tool refresh rewrote early material/header/native code")
            if "Building CXX object" in output or "Linking CXX" in output:
                raise AssertionError("late data-only input triggered native codegen/link feedback")
            final = args.image.read_bytes()
            if final == original_final or verifier(args.raw_image.read_bytes(), final, plan, material, draft) != json.loads(args.report.read_text()):
                raise AssertionError(f"late completion missed {dependency.name} dependency or lost final-byte proof")
        finally:
            os.utime(dependency, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        settled = snapshot(), args.image.read_bytes(), args.report.read_bytes()
        output = run(command).stdout
        if "no work to do" not in output or (snapshot(), args.image.read_bytes(), args.report.read_bytes()) != settled:
            raise AssertionError("measured dependency chain does not settle to a no-change build")
    print("late plan/scoped-tool refresh changes only authenticated final data; early/code inputs stable and no-change chains settle")
