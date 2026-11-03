"""Native storage/real crypto support and data completion for isolated session tests."""

from pathlib import Path
import subprocess

from cff_build import run
from pe_release_record import finalize_image
from atomic_artifact import atomic_write
from session_fold_reference import diagnostic_output


def native_support(args, directory: Path, root: Path):
    result = []
    for name, source, define in (
            ("record", "backends/windows_user/release_record.cpp", None),
            ("hash", "backends/windows_user/operations/hash.cpp", "hash_sha256=hash_sha256_actual"),
            ("crypto", "backends/windows_user/operations/crypto.cpp", "decrypt_payload=decrypt_payload_actual")):
        output = directory / (name + ".obj")
        run([args.compiler, "-std=c++17", "-O2", "-fno-lto" if name == "record" or not args.ipo else "-flto=thin",
             "-I", root / "include", "-I", root / "src", *(["-D" + define] if define else []),
             "-c", root / source, "-o", output])
        result.append(output)
    return result


def complete_binary(source: Path, output: Path, record_path: Path):
    finalized, report = finalize_image(source.read_bytes(), record_path.read_bytes())
    atomic_write(output, finalized)
    return report


def session_output(binary: Path, *arguments):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise AssertionError(f"native session failed ({result.returncode}):\n{diagnostic_output(result.stdout)}\n{result.stderr}")
    return result.stdout
