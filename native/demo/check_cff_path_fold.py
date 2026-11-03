"""Execute the production fold emitter and C++ model against independent build references."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import path_fold_reference as fold


def run(command, *, succeeds=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=45)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"path-fold command result differs: {command}\n{result.stdout}\n{result.stderr}")
    return result


def finish(seed, events):
    state = fold.initialize(seed)
    for tag, word in events:
        state = fold.advance(state, tag, word)
    return state


def references(path):
    if (fold.VERSION != 1 or fold.initialize(0) != (0x01fce552, 0x04f8d29e, 0x0f8c1dbd, 0x6ba5a157,
            0x057fb7f9, 0x5ea4fb47, 0x9173a5e2, 0x60f3d8ca) or
            fold.advance(fold.initialize(0), 0, 0) != (0xa2ca280c, 0x54f407da, 0x51a75678, 0x84a01668,
            0xd63124cb, 0x415d9f5c, 0x7e836d85, 0x437d0721) or
            fold.encode_word(0x13579bdf, 0x2468ace0, 0x5a91c37d) != 0xc81822f5):
        raise AssertionError("version1 pinned arithmetic vectors changed")
    boundary = [0, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff, 0xaaaaaaaa, 0x55555555]
    randomizer = random.Random(0x7ad39135)
    cases = [(seed, [(boundary[index], boundary[-1-index]) for index in range(len(boundary))]) for seed in boundary]
    cases += [(randomizer.getrandbits(32), [(randomizer.getrandbits(32), randomizer.getrandbits(32))
                for _ in range(index % 25)]) for index in range(128)]
    transcript = [(0x100 + index, 0x912bca71 ^ (index * 0x1020304)) for index in range(6)]
    normal = finish(0x13579bdf, transcript)
    mutants = []
    for index in range(len(transcript)):
        mutants.append(transcript[:index] + transcript[index+1:])
        mutants.append(transcript[:index] + [transcript[index]] + transcript[index:])
        changed = list(transcript)
        tag, word = changed[index]
        changed[index] = tag, word ^ 1
        mutants.append(changed)
        changed = list(transcript)
        changed[index] = tag ^ 1, word
        mutants.append(changed)
        if index + 1 < len(transcript):
            changed = list(transcript)
            changed[index], changed[index+1] = changed[index+1], changed[index]
            mutants.append(changed)
    if any(finish(0x13579bdf, events) == normal for events in mutants):
        raise AssertionError("named transcript skip/reorder/duplicate/data/site mutation did not perturb fold")
    cases += [(0x13579bdf, transcript), *((0x13579bdf, events) for events in mutants)]
    # This pair would cancel if the label and value were first collapsed into one XOR word.
    if finish(1, [(3, 5)]) == finish(1, [(2, 5 ^ (1 << 11))]):
        raise AssertionError("site label can be trivially canceled by the word input")
    cases += [(1, [(3, 5)]), (1, [(2, 5 ^ (1 << 11))])]
    lines = [str(len(cases))]
    for seed, events in cases:
        state = fold.initialize(seed)
        lines += [f"{seed} {len(events)}", " ".join(map(str, state))]
        for tag, word in events:
            state = fold.advance(state, tag, word)
            lines.append(" ".join(map(str, (tag, word, *state))))
        serialized = fold.serialize(state)
        if serialized != b"".join(word.to_bytes(4, "little") for word in state):
            raise AssertionError("canonical fold serialization changed")
        lines.append(" ".join(map(str, serialized)))
    encoded = fold.encode_word(0x13579bdf, 0x2468ace0, 0x5a91c37d)
    currents = boundary + [0x2468ace0] + [0x2468ace0 ^ (1 << bit) for bit in range(32)]
    currents += [randomizer.getrandbits(32) for _ in range(512)]
    lines.append(str(len(currents)))
    for current in currents:
        value = fold.decode_word(encoded, current, 0x5a91c37d)
        if (value == 0x13579bdf) != (current == 0x2468ace0):
            raise AssertionError("event decoding lost its current-state dependency")
        lines.append(f"{current} {value}")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    for bad in (-1, 1 << 32, True, 1.0):
        for operation in (lambda: fold.initialize(bad), lambda: fold.advance((0,) * 8, bad, 0),
                          lambda: fold.encode_word(0, bad, 0)):
            try: operation()
            except ValueError: pass
            else: raise AssertionError("malformed build word was silently truncated")
    try: fold.serialize((0,) * 7)
    except ValueError: pass
    else: raise AssertionError("malformed state length was serialized")
    return len(cases), len(currents), len(mutants)


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "generator", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--ipo", action="store_true")
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, vectors = directory / "fold.ll", directory / "vectors.txt"
        counts = references(vectors)
        run([args.generator, source])
        rejected = directory / "invalid.ll"
        invalid = run([args.generator, rejected, "invalid-width"], succeeds=False)
        if rejected.exists() or "path fold needs an i32 value" not in invalid.stderr:
            raise AssertionError("unsupported input width was not refused before output")
        invalid = run([args.generator, rejected, "invalid-storage"], succeeds=False)
        if rejected.exists() or "path fold needs pointer storage" not in invalid.stderr:
            raise AssertionError("unsupported storage type was not refused before output")
        run([args.opt, "-passes=verify", "-disable-output", source])
        text = source.read_text()
        if re.search(r"\b(?:nsw|nuw|exact)\b", text):
            raise AssertionError("fold arithmetic added poison-producing flags")
        body = re.search(r"define void @fold_step\(.*?\n\}", text, re.S)
        if body is None or body.group().count("load volatile i32") != 8 or body.group().count("store volatile i32") != 8:
            raise AssertionError("fold snapshot does not use eight runtime reads and writes")
        if body.group().rfind("load volatile i32") > body.group().find("store volatile i32"):
            raise AssertionError("fold overwrites lanes before capturing the old snapshot")
        for profile in ("none", "O2"):
            optimized = source
            if profile == "O2":
                optimized = directory / "fold.O2.ll"
                run([args.opt, "-passes=default<O2>", "-verify-each", "-S", source, "-o", optimized])
            binary = directory / f"fold.{profile}.exe"
            command = [args.compiler, "-std=c++17", "-O2", "-I", ROOT / "src", optimized,
                       ROOT / "tests/path_fold_harness.cpp", *(["-flto=thin"] if args.ipo else []), "-o", binary]
            run(command)
            if "host/runtime/emitter verified" not in run([binary, vectors]).stdout:
                raise AssertionError("actual emitted fold was not executed")
        broken, replaced = re.subn(r"store volatile i32 (%[^,\s]+),", "store volatile i32 0,", text, count=1)
        if replaced != 1: raise AssertionError("missing generated initialization store")
        altered = directory / "altered.ll"
        altered.write_text(broken)
        executable = directory / "altered.exe"
        run([args.compiler, "-std=c++17", "-O2", "-I", ROOT / "src", altered,
             ROOT / "tests/path_fold_harness.cpp", "-o", executable])
        run([executable, vectors], succeeds=False)
        print(f"path-fold v1: {counts[0]} transcripts, {counts[1]} state bindings, {counts[2]} path mutations; none/O2, IPO={args.ipo}")


if __name__ == "__main__":
    main()
