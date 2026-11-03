"""Execute the production IR-expression emitters at u32 boundaries and host reference vectors."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path


def run(command: list[str], *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"expression contract result differs: {command}\n{result.stderr}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "generator", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "expressions.ll"
        vectors = directory / "vectors.json"
        run([str(args.generator), str(source), str(vectors)])
        run([str(args.opt), "-passes=verify", "-disable-output", str(source)])
        records = json.loads(vectors.read_text())
        declarations = "\n".join(
            f'extern "C" std::uint32_t {name}_{index}(std::uint32_t);'
            for name, indices in (("opaque", range(3)), ("junk", range(1, 9))) for index in indices)
        values = ",\n".join(
            "{" + str(row["input"]) + "u,{" + ",".join(f"{value}u" for value in row["junk"]) + "}}"
            for row in records)
        checks = "\n".join(f"if (opaque_{index}(row.value) != 1) return 1;" for index in range(3))
        checks += "\n" + "\n".join(
            f"if (junk_{rounds}(row.value) != row.expected[{rounds - 1}]) return 2;"
            for rounds in range(1, 9))
        harness = directory / "harness.cpp"
        harness.write_text(
            "#include <cstdint>\n" + declarations +
            "\nstruct Row { std::uint32_t value; std::uint32_t expected[8]; };\n" +
            "const Row rows[] = {\n" + values + "\n};\nint main(){for(const auto &row:rows){\n" +
            checks + "\n}return 0;}\n", encoding="utf-8")
        binary = directory / "expressions.exe"
        run([str(args.compiler), str(source), str(harness), "-o", str(binary)])
        run([str(binary)])
        text = source.read_text(encoding="utf-8")
        body = re.search(r"define i32 @opaque_0\(.*?\n\}", text, re.S)
        if body is None:
            raise AssertionError("production opaque emitter is missing")
        altered, count = re.subn(
            r"(%pyobf\.opaque\.second = )load volatile i32, ptr %state(?:, align \d+)?",
            r"\1xor i32 %input, 1", body.group(), count=1)
        if count != 1:
            raise AssertionError("predicate does not use independent correlated runtime reads")
        broken = directory / "broken.ll"
        broken.write_text(text[:body.start()] + altered + text[body.end():], encoding="utf-8")
        wrong = directory / "broken.exe"
        run([str(args.compiler), str(broken), str(harness), "-o", str(wrong)])
        run([str(wrong)], succeeds=False)


if __name__ == "__main__":
    main()
