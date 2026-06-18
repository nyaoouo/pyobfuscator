#!/usr/bin/env python3
"""Performance benchmark harness for pyobfuscator.

For each obfuscation / protection configuration this measures four costs and compares them
against a baseline:

  * build time      - wall time of ``obf_module()`` (median of B runs, build warnings silenced)
  * output size     - bytes of the emitted artifact (text encoded utf-8, or raw .pyc bytes)
  * body runtime    - the artifact's own self-timed hot loop, run in a killable subprocess
                      (median of M runs), reported as an x-overhead vs the unobfuscated source
  * startup/decrypt - subprocess wall - body runtime - empty-interpreter boot: the one-time
                      launcher decrypt + exec (+ decompress) cost, where the protect layer lives

A per-run CHECKSUM printed by each workload is compared to the unobfuscated baseline; a mismatch
(or a subprocess timeout / non-zero exit) marks the row ``diverged`` and its timings are not
trusted. Wrong-path bodies can busy-loop in the dispatcher, so every run is a subprocess with a
timeout (never an in-process exec / thread).

Usage::

    .venv/Scripts/python bench/benchmark.py             # full matrix, both workloads
    .venv/Scripts/python bench/benchmark.py --quick     # small subset, fewer reps (dev)

Writes ``bench/results.json`` (machine-readable, the provenance for any doc numbers) and
``bench/results.md`` (rendered tables), and prints the tables to stdout. Absolute numbers are
machine-dependent; regenerate on the target machine.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
WORKLOAD_DIR = os.path.join(HERE, "workloads")
REPO_ROOT = os.path.dirname(HERE)

# The package is normally an editable install in the venv; fall back to the src/ tree.
try:
    from pyobfuscator import obf_module, ModuleObfOptions
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
    from pyobfuscator import obf_module, ModuleObfOptions

SEED = 20260618
RUN_TIMEOUT = 25.0

WORKLOADS = [
    ("cpu", os.path.join(WORKLOAD_DIR, "cpu_workload.py")),
    ("str", os.path.join(WORKLOAD_DIR, "str_workload.py")),
]

# Plain flattening with every shaping flag off — the reference for isolating each CFF flag's cost.
CFF_OFF = dict(
    obf_strings=False, obf_ints=False, shuffle_states=False, opaque_predicates=False,
    bogus_blocks=False, slot_vars=False, stack_calls=False, hide_external_args=False,
    split_calls=False, return_var=False, dedup=False, state_delta=False, dispatch_tree=False,
    junk_code=False, dict_indirect=False, const_archive=False, name_vault=False,
    name_vault_attrs=False, hide_compares=False,
)

CFF_SINGLE = [
    "obf_strings", "obf_ints", "shuffle_states", "opaque_predicates", "bogus_blocks",
    "slot_vars", "stack_calls", "hide_external_args", "return_var", "dedup", "state_delta",
    "dispatch_tree", "junk_code", "dict_indirect", "const_archive", "name_vault", "hide_compares",
]

PROTECT_SINGLE = [
    ("integrity_selfcheck", {"integrity_selfcheck": True}),
    ("cohash_integrity (text: version-locks)", {"cohash_integrity": True}),
    ("pack_decoy", {"pack_decoy": True}),
    ("obf_imports", {"obf_imports": True}),
    ("detect_trace (+key_binds_env)", {"key_binds_env": True, "detect_trace": True}),
    ("detect_tools (+key_binds_env)", {"key_binds_env": True, "detect_tools": True}),
    ("detect_env (+key_binds_env)", {"key_binds_env": True, "detect_env": True}),
    ("detect_stack (+key_binds_env)", {"key_binds_env": True, "detect_stack": True}),
    ("detect_audit", {"detect_audit": True}),
    ("anti_trace_neuter", {"anti_trace_neuter": True}),
    ("anti_trace_neuter +honeypot", {"anti_trace_neuter": True, "anti_trace_neuter_honeypot": True}),
    ("attest (density 0.3)", {"attest": True}),
    ("attest +runtime_bind", {"attest": True, "attest_runtime_bind": True}),
    ("compress_output", {"compress_output": True}),
    ("compress_output rounds=2", {"compress_output": True, "compress_rounds": 2}),
    ("require_min_python", {"require_min_python": True}),
]


def build_matrix(quick):
    """Return a list of (section, label, output, opts) configurations."""
    pb = dict(pack_body=True, key_from_cff=True)        # protect base
    rows = []

    # --- CFF layer (output=text) ---
    rows.append(("CFF", "baseline (plain flatten, all CFF flags off)", "text", dict(CFF_OFF)))
    rows.append(("CFF", "defaults (obf_strings+shuffle+opaque+bogus)", "text", {}))
    singles = ["obf_strings", "opaque_predicates", "bogus_blocks", "const_archive",
               "dispatch_tree"] if quick else CFF_SINGLE
    for f in singles:
        rows.append(("CFF", f, "text", {**CFF_OFF, f: True}))
    if not quick:
        rows.append(("CFF", "split_calls (+hide_external_args)", "text",
                     {**CFF_OFF, "hide_external_args": True, "split_calls": True}))
        rows.append(("CFF", "name_vault_attrs (+name_vault)", "text",
                     {**CFF_OFF, "name_vault": True, "name_vault_attrs": True}))

    # --- Protect layer (output=text), marginal over pack_body+key_from_cff ---
    rows.append(("Protect", "base (pack_body+key_from_cff)", "text", dict(pb)))
    protect = (PROTECT_SINGLE[:4] + [("attest", {"attest": True}),
               ("compress_output", {"compress_output": True})]) if quick else PROTECT_SINGLE
    for label, extra in protect:
        rows.append(("Protect", label, "text", {**pb, **extra}))

    # --- PYC-only: body_cohash (needs attest + pyc) ---
    rows.append(("Protect-PYC", "base (pyc, attest)", "pyc", {**pb, "attest": True}))
    rows.append(("Protect-PYC", "body_cohash (pyc, attest)", "pyc",
                 {**pb, "attest": True, "body_cohash": True}))

    # --- Presets (output=text) ---
    for lvl in ["off", "light", "full"]:
        rows.append(("Presets", "protect_level=%s" % lvl, "text", {"protect_level": lvl}))

    # --- Knob sweeps ---
    if not quick:
        for d in [0.1, 0.3, 0.6, 1.0]:
            rows.append(("Knobs", "attest_density=%s" % d, "text",
                         {**pb, "attest": True, "attest_density": d}))
        for r in [1, 2, 3]:
            rows.append(("Knobs", "compress_rounds=%d" % r, "text",
                         {**pb, "compress_output": True, "compress_rounds": r}))
        for mb in [2, 4, 8]:
            rows.append(("Knobs", "min_blocks=%d" % mb, "text", {"min_blocks": mb}))
    return rows


# ----------------------------------------------------------------------------- measurement
def _as_bytes(artifact):
    return artifact.encode("utf-8") if isinstance(artifact, str) else artifact


def build_artifact(src, output, opts, reps):
    """Build `reps` times; return (artifact, median_build_seconds). Build warnings (e.g. the
    cohash/TEXT version-lock notice) are silenced so they don't pollute the run."""
    times, art = [], None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for _ in range(reps):
            t0 = time.perf_counter()
            art = obf_module(src, ModuleObfOptions(seed=SEED, output=output, **opts))
            times.append(time.perf_counter() - t0)
    return art, statistics.median(times)


def _parse_line(stdout, prefix):
    for line in stdout.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def run_once(path, timeout=RUN_TIMEOUT):
    """Run `python <path>` in a killable subprocess. Returns (elapsed, checksum, wall, status)."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.run([sys.executable, path], capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, None, None, "timeout"
    wall = time.perf_counter() - t0
    el = _parse_line(proc.stdout, "ELAPSED=")
    cs = _parse_line(proc.stdout, "CHECKSUM=")
    if proc.returncode != 0 or el is None or cs is None:
        return None, None, wall, "error"
    return float(el), int(cs), wall, "ok"


def run_artifact(artifact, output, reps):
    """Run an artifact `reps` times; return (median_elapsed, checksum, median_wall, status)."""
    suffix = ".pyc" if output == "pyc" else ".py"
    fd, path = tempfile.mkstemp(suffix=suffix, dir=tempfile.gettempdir())
    os.close(fd)
    mode = "wb" if output == "pyc" else "w"
    data = _as_bytes(artifact) if output == "pyc" else artifact
    kw = {} if output == "pyc" else {"encoding": "utf-8"}
    try:
        with open(path, mode, **kw) as fh:
            fh.write(data)
        elapsed, walls, checksum, status = [], [], None, "error"
        for _ in range(reps):
            el, cs, wall, st = run_once(path)
            if st == "ok":
                elapsed.append(el)
                walls.append(wall)
                checksum = cs
                status = "ok"
            elif status != "ok":
                status = st
        if status != "ok":
            return None, None, None, status
        return statistics.median(elapsed), checksum, statistics.median(walls), "ok"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def boot_baseline(reps):
    walls = []
    for _ in range(reps):
        t0 = time.perf_counter()
        subprocess.run([sys.executable, "-c", "pass"], capture_output=True, timeout=RUN_TIMEOUT)
        walls.append(time.perf_counter() - t0)
    return statistics.median(walls)


def measure(label, section, output, opts, src, reps_build, reps_run, raw_runtime, raw_checksum, boot):
    """Build + size + run one configuration; return a result row dict."""
    row = {"section": section, "label": label, "output": output}
    try:
        artifact, build_s = build_artifact(src, output, opts, reps_build)
    except Exception as exc:                                   # a rejected combo, etc.
        row.update(build_ms=None, size_b=None, runtime_x=None, startup_ms=None,
                   status="build-error", detail=type(exc).__name__ + ": " + str(exc)[:120])
        return row
    row["build_ms"] = round(build_s * 1000, 1)
    row["size_b"] = len(_as_bytes(artifact))
    runtime_s, checksum, wall, status = run_artifact(artifact, output, reps_run)
    if status != "ok":
        row.update(runtime_x=None, startup_ms=None, status=status)
        return row
    if checksum != raw_checksum:
        row.update(runtime_x=round(runtime_s / raw_runtime, 2) if raw_runtime else None,
                   startup_ms=None, status="diverged")
        return row
    startup = max(0.0, wall - runtime_s - boot)
    row.update(runtime_x=round(runtime_s / raw_runtime, 2) if raw_runtime else None,
               startup_ms=round(startup * 1000, 1), status="ok")
    return row


# ----------------------------------------------------------------------------- rendering
COLS = [("label", "Config", "<"), ("build_ms", "build (ms)", ">"), ("size_b", "size (B)", ">"),
        ("runtime_x", "runtime (×raw)", ">"), ("startup_ms", "startup (ms)", ">"),
        ("status", "status", "<")]


def _fmt(v):
    return "-" if v is None else (str(v) if not isinstance(v, float) else ("%g" % v))


def render_markdown(results):
    meta = results["meta"]
    out = ["# pyobfuscator - measured performance", "",
           "Generated by `bench/benchmark.py`. Absolute numbers are machine-dependent; regenerate "
           "on the target machine.", "",
           "- Python: `%s`" % meta["python"],
           "- Platform: `%s`" % meta["platform"],
           "- Processor: `%s`" % (meta["processor"] or "n/a"),
           "- Seed: `%d`  -  build reps: %d  -  run reps: %d" % (meta["seed"], meta["build_reps"], meta["run_reps"]),
           "- Empty-interpreter boot baseline: %.1f ms" % (meta["boot_s"] * 1000), ""]
    for wl in results["workloads"]:
        name = wl["name"]
        out.append("## Workload: `%s`" % name)
        out.append("")
        out.append("Unobfuscated baseline: runtime **%.1f ms**, source **%d B**, checksum `%d`."
                   % (wl["raw_runtime_s"] * 1000, wl["raw_size_b"], wl["raw_checksum"]))
        out.append("")
        sections = []
        for r in wl["rows"]:
            if r["section"] not in sections:
                sections.append(r["section"])
        for sec in sections:
            out.append("### %s" % sec)
            out.append("")
            out.append("| " + " | ".join(c[1] for c in COLS) + " |")
            out.append("|" + "|".join("---" for _ in COLS) + "|")
            for r in wl["rows"]:
                if r["section"] != sec:
                    continue
                out.append("| " + " | ".join(_fmt(r.get(c[0])) for c in COLS) + " |")
            out.append("")
    return "\n".join(out)


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="pyobfuscator performance benchmark")
    ap.add_argument("--quick", action="store_true", help="small subset + fewer reps (dev)")
    args = ap.parse_args()

    reps_build = 1 if args.quick else 3
    reps_run = 2 if args.quick else 4
    boot_reps = 3 if args.quick else 5

    print("[bench] boot baseline ...", flush=True)
    boot = boot_baseline(boot_reps)
    print("[bench] boot = %.1f ms" % (boot * 1000), flush=True)

    matrix = build_matrix(args.quick)
    results = {
        "meta": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor(),
            "seed": SEED,
            "build_reps": reps_build,
            "run_reps": reps_run,
            "boot_s": boot,
            "quick": args.quick,
        },
        "workloads": [],
    }

    for wl_name, wl_path in WORKLOADS:
        with open(wl_path, encoding="utf-8") as fh:
            src = fh.read()
        raw_rt, raw_cs, _, raw_status = run_artifact(src, "text", max(reps_run, 3))
        if raw_status != "ok":
            print("[bench] FATAL: raw workload %s did not run (%s)" % (wl_name, raw_status))
            sys.exit(1)
        wl = {"name": wl_name, "raw_runtime_s": raw_rt, "raw_checksum": raw_cs,
              "raw_size_b": len(src.encode("utf-8")), "rows": []}
        print("\n[bench] workload '%s': raw runtime %.1f ms, %d configs"
              % (wl_name, raw_rt * 1000, len(matrix)), flush=True)
        for i, (section, label, output, opts) in enumerate(matrix, 1):
            row = measure(label, section, output, opts, src, reps_build, reps_run,
                          raw_rt, raw_cs, boot)
            wl["rows"].append(row)
            print("  [%2d/%d] %-12s %-42s build=%-7s size=%-8s rt=%-6s start=%-7s %s"
                  % (i, len(matrix), section, label[:42],
                     _fmt(row.get("build_ms")), _fmt(row.get("size_b")),
                     _fmt(row.get("runtime_x")), _fmt(row.get("startup_ms")), row["status"]),
                  flush=True)
        results["workloads"].append(wl)

    json_path = os.path.join(HERE, "results.json")
    md_path = os.path.join(HERE, "results.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    md = render_markdown(results)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    print("\n" + md)
    print("\n[bench] wrote %s and %s" % (os.path.relpath(json_path, REPO_ROOT),
                                         os.path.relpath(md_path, REPO_ROOT)))

    diverged = [(w["name"], r["label"], r["status"]) for w in results["workloads"]
                for r in w["rows"] if r["status"] not in ("ok",)]
    if diverged:
        print("\n[bench] NON-OK ROWS (%d):" % len(diverged))
        for name, label, st in diverged:
            print("  %-5s %-44s %s" % (name, label[:44], st))


if __name__ == "__main__":
    main()
