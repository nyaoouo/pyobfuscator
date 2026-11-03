"""Exercise the production packer CLI, metadata binding, private outputs and invalid inputs."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from archive_format import ACCESS_DOMAIN, BODY_DOMAIN, CORE, HEADER, MAGIC, RECORD_BYTES, parse_plan
from archive_fixture import records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    tool = Path(__file__).resolve().parents[1] / "tools" / "pack_archive.py"
    plan = {"schema_version": 1, "records": [
        {"id": record.identity, "kind": record.kind.name, "bit_width": record.bit_width,
         "alignment": record.alignment, "byte_order": record.byte_order, "data_hex": record.data.hex()}
        for record in records()]}
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "plan.json"
        package_path, cpp, bindings_path = directory / "package.bin", directory / "package.cpp", directory / "bindings.json"

        def invoke(value: dict, *, succeeds: bool = True):
            source.write_text(json.dumps(value), encoding="utf-8")
            for output in (package_path, cpp, bindings_path): output.unlink(missing_ok=True)
            result = subprocess.run([sys.executable, str(tool), str(source), str(package_path), str(cpp), str(bindings_path)],
                                    capture_output=True, text=True, timeout=20)
            if (result.returncode == 0) != succeeds:
                raise AssertionError(f"archive tool result differs: {result.stderr}")
            if not succeeds:
                if any(output.exists() for output in (package_path, cpp, bindings_path)):
                    raise AssertionError("invalid archive plan produced partial outputs")
                return result
            if "key_hex" in result.stdout or "protected-native-bytes" in result.stdout:
                raise AssertionError("archive tool printed private key/data material")
            return package_path.read_bytes(), json.loads(bindings_path.read_text())

        data, bindings = invoke(plan)
        magic, version, count, identity, total = HEADER.unpack(data[:HEADER.size])
        if (magic != MAGIC or version != 1 or count != len(plan["records"]) or total != len(data) or
            bindings["archive_id"] != identity.hex() or bindings["package_sha256"] != hashlib.sha256(data).hexdigest() or
            bindings["plan_sha256"] != hashlib.sha256(source.read_bytes()).hexdigest()):
            raise AssertionError("archive header and private bindings disagree")
        for index, record in enumerate(parse_plan(plan)):
            descriptor = data[HEADER.size + index * RECORD_BYTES:HEADER.size + (index + 1) * RECORD_BYTES]
            core = descriptor[:CORE.size]
            _, _, _, _, size, offset, _, _ = CORE.unpack(core)
            key = bytes.fromhex(bindings["records"][index]["key_hex"])
            plain = AESGCM(key).decrypt(descriptor[40:52], data[offset:offset + size] + descriptor[52:68],
                                        BODY_DOMAIN + data[:HEADER.size] + core)
            access = AESGCM(key).decrypt(descriptor[68:80], descriptor[80:96],
                                         ACCESS_DOMAIN + data[:HEADER.size] + descriptor[:68])
            if plain != record.data or access != b"" or key in data or key.hex() in cpp.read_text():
                raise AssertionError("typed archive record/empty access authentication or key privacy differs")
        other, fresh = invoke(plan)
        if other == data or fresh["archive_id"] == bindings["archive_id"] or any(
                left["key_hex"] == right["key_hex"] for left, right in zip(bindings["records"], fresh["records"])):
            raise AssertionError("archive entropy was reused across independent builds")
        bad_plans = [dict(plan, schema_version=True), dict(plan, unknown_field=0), dict(plan, records=[])]
        duplicate = copy.deepcopy(plan)
        duplicate["records"][1]["id"] = duplicate["records"][0]["id"]
        bad_plans.append(duplicate)
        for field, value in (("kind", "unknown"), ("bit_width", 0), ("alignment", 3),
                             ("byte_order", 99), ("data_hex", "abc"), ("alignment", True)):
            bad = copy.deepcopy(plan)
            bad["records"][2][field] = value
            bad_plans.append(bad)
        for bad in bad_plans: invoke(bad, succeeds=False)
        source.write_text(json.dumps(plan), encoding="utf-8")
        result = subprocess.run([sys.executable, str(tool), str(source), str(source), str(cpp), str(bindings_path)],
                                capture_output=True, text=True, timeout=20)
        if result.returncode == 0 or json.loads(source.read_text()) != plan:
            raise AssertionError("colliding output paths overwrote the private input plan")


if __name__ == "__main__":
    main()
