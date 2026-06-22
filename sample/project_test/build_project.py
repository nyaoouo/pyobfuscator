"""Multi-module demo build + self-verification.

Obfuscates the demo project under ``src/`` with the full protection stack into ``dist/`` (git-ignored)
via ``obf_project``, then verifies, against the SHIPPED dist tree:

  1. genuine run               python dist/main.py <key> <payload> -> OK:... / DENIED
  2. reverse import            app/logic.py (plaintext) imports the protected app/secret
  3. update only secret        rebuild ONLY secret (same seed); the old entry runs the new satellite
  4. tamper the entry          corrupt dist/main.py -> genuine output gone
  5. tamper a satellite        corrupt dist/app/secret.py -> that module breaks
  6. traced load               a debugger/settrace at load -> decoy (real output gone)
  7. foreign import            import app.secret WITHOUT the entry -> fail (entry-bound)

Run (from this directory) with the project venv:
    ../../.venv/Scripts/python build_project.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))  # <repo>/src (the pyobfuscator package)

from pyobfuscator import obf_project, ModuleObfOptions, analyze_html, protect_html

SRC = os.path.join(HERE, "src")
DIST = os.path.join(HERE, "dist")
BUILD = os.path.join(HERE, "build")     # analyze HTML deliverables (git-ignored)
SEED = 2026
KEY = "PYOBF-PRO-2026"   # default license key injected at build; override with --key on the CLI
ENTRY = os.path.join(DIST, "main.py")
SECRET = os.path.join(DIST, "app", "secret.py")


def _opts():
    # Full stack: encrypting packer + cff-derived key + branchless decoy + cff<->python attestation +
    # anti-trace honeypot (a tracer at load -> decoy). obf_imports hides the launcher's own imports.
    return ModuleObfOptions(
        output="text", seed=SEED,
        # Build-time injection: app/secret.py reads the license key via precompile_arg("LICENSE_KEY")
        # and folds _scramble(key) through precompile, so the key never appears in the shipped source.
        precompile_args={"LICENSE_KEY": KEY},
        pack_body=True, key_from_cff=True, integrity_selfcheck=True, pack_decoy=True,
        attest=True, attest_runtime_bind=True, detect_audit=True, anti_trace_neuter=True,
        detect_trace=True, key_binds_env=True, obf_imports=True, compress_output=True, compress_rounds=5)


# Never let a stale .pyc cache mask a tampered .py: an earlier genuine run caches app/secret.pyc, and a
# rebuilt secret.py can share its (coarse, on Windows) mtime, so Python would load the CLEAN cached
# bytecode and ignore a later corruption. Clean __pycache__ on every build and disable writing for runs.
_ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}


def _clean_pycache(root):
    for dirpath, dirs, _files in os.walk(root):
        if os.path.basename(dirpath) == "__pycache__":
            shutil.rmtree(dirpath, ignore_errors=True)


def _build(src, dist):
    obf_project(root=src, out=dist, entry="main.py", protect=["app/secret.py"], options=_opts())
    _clean_pycache(dist)


def _run(path, *args, timeout=90):
    r = subprocess.run([sys.executable, path, *args], capture_output=True, text=True,
                       timeout=timeout, env=_ENV)
    return r.stdout, r.returncode


def _run_traced(path, *args, timeout=90):
    """Run the entry with sys.settrace ACTIVE before it loads (the debugger-at-load shape)."""
    probe = ("import sys, runpy\n"
             "sys.settrace(lambda f, e, a: None)\n"
             "sys.argv = [%r, %r, %r]\n"
             "try:\n    runpy.run_path(%r, run_name='__main__')\n"
             "except SystemExit:\n    pass\n"
             "except BaseException as ex:\n    print('EXC:', type(ex).__name__)\n"
             % (path, args[0] if args else "", args[1] if len(args) > 1 else "", path))
    pf = tempfile.NamedTemporaryFile("w", suffix="_traced.py", delete=False, encoding="utf-8")
    pf.write(probe)
    pf.close()
    try:
        r = subprocess.run([sys.executable, pf.name], capture_output=True, text=True,
                           timeout=timeout, env=_ENV)
        return r.stdout
    except subprocess.TimeoutExpired:
        return "__HANG__"           # busy-loop = diverged = protected
    finally:
        os.unlink(pf.name)


def _foreign_import(dist, modname, timeout=30):
    probe = ("import sys\n"
             "sys.path.insert(0, %r)\n"
             "try:\n    __import__(%r)\n    print('LOADED')\n"
             "except BaseException as e:\n    print('FAILED', type(e).__name__)\n" % (dist, modname))
    try:
        r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                           timeout=timeout, env=_ENV)
        return r.stdout
    except subprocess.TimeoutExpired:
        return "__HANG__"
    finally:
        pass


def _corrupt_blobs(path):
    """Flip an EARLY character in EVERY large ``b'...'`` byte literal (the encrypted body blob plus
    its bogus clones from ``bogus_blocks``). The real blob is among them and its real slice ``e_real``
    lives at offset 0, so an early flip reliably triggers a b85/zlib failure on the genuine decrypt
    path. Corrupting the bogus clones is harmless (they never run) — and since an attacker can't tell
    which blob is real, ANY edit to a blob breaks the artifact. The b85 alphabet has no single quote,
    so ``b'[^']*'`` matches each literal cleanly."""
    data = open(path, encoding="utf-8").read()
    spans = [m for m in re.finditer(r"b'[^']*'", data) if (m.end() - m.start()) >= 16]
    if not spans:
        return False
    out, last = [], 0
    for m in spans:
        pos = m.start() + 2 + 8                         # early -> inside e_real (offset 0), not the decoy
        out.append(data[last:pos])
        out.append("Z" if data[pos] != "Z" else "Y")
        last = pos + 1
    out.append(data[last:])
    open(path, "w", encoding="utf-8").write("".join(out))
    return True


def _ensure_build_dir():
    """Create BUILD and a dir-scope .gitignore (idempotent) so the analyze HTML stays untracked."""
    os.makedirs(BUILD, exist_ok=True)
    gi = os.path.join(BUILD, ".gitignore")
    if not os.path.exists(gi):
        open(gi, "w", encoding="utf-8").write(
            "# Analyze deliverables (generated by build_project.py)\n*\n!.gitignore\n")


def _emit_analysis():
    """Write the debug visualizations for the obfuscated modules into build/ (git-ignored): a CFF
    'mind map' (analyze_html) and a packer-shell layer breakdown (protect_html) for the entry and the
    protected satellite. Uses the same options as the build, so precompile_arg/precompile fold the same
    way (the analyze view runs the real pipeline)."""
    _ensure_build_dir()
    opts = _opts()
    targets = (("main", os.path.join(SRC, "main.py")),
               ("secret", os.path.join(SRC, "app", "secret.py")))
    written = []
    for label, path in targets:
        src = open(path, encoding="utf-8").read()
        pages = (("analyze", analyze_html(src, opts, title="%s — pyobfuscator analyze (CFF)" % label)),
                 ("protect", protect_html(src, opts, title="%s — pyobfuscator protect (shell)" % label)))
        for kind, page in pages:
            dest = os.path.join(BUILD, "%s_%s.html" % (label, kind))
            open(dest, "w", encoding="utf-8").write(page)
            written.append((dest, len(page.encode("utf-8"))))
    print("  analyze HTML (build/, git-ignored):")
    for dest, nbytes in written:
        print("    %s (%dB)" % (os.path.relpath(dest, HERE).replace(os.sep, "/"), nbytes))


def main():
    fails = []

    def check(ok, label, detail=""):
        print("  [%s] %s%s" % ("OK " if ok else "XX ", label, (" -> " + detail) if detail else ""))
        if not ok:
            fails.append(label)

    # 1. build + genuine run (reverse import logic->secret is exercised here too)
    _build(SRC, DIST)
    out, rc = _run(ENTRY, KEY, "hello")
    check(rc == 0 and "OK:OLLEH" in out, "genuine: correct key", repr(out.strip()))
    out_d, _ = _run(ENTRY, KEY + "-WRONG", "hello")   # any key != the injected one
    check("DENIED" in out_d and "OK:" not in out_d, "genuine: wrong key -> DENIED", repr(out_d.strip()))

    # 3. update ONLY secret: rebuild a modified secret (same seed) into a temp dist, swap its
    #    secret.py into the existing dist, and confirm the unchanged entry runs the NEW satellite.
    tmp_src = tempfile.mkdtemp(prefix="pp_src_")
    tmp_dist = tempfile.mkdtemp(prefix="pp_dist_")
    try:
        shutil.copytree(SRC, tmp_src, dirs_exist_ok=True)
        sec = os.path.join(tmp_src, "app", "secret.py")
        s = open(sec, encoding="utf-8").read().replace(
            "return payload[::-1].upper()", "return '[' + payload[::-1].upper() + ']'")
        open(sec, "w", encoding="utf-8").write(s)
        _build(tmp_src, tmp_dist)
        # the entry is independent of secret's content (s_correct = f(seed)) -> byte-identical
        same_entry = (open(ENTRY).read() == open(os.path.join(tmp_dist, "main.py")).read())
        check(same_entry, "update-secret: entry unchanged across rebuilds (determinism)")
        shutil.copyfile(os.path.join(tmp_dist, "app", "secret.py"), SECRET)
        out2, rc2 = _run(ENTRY, KEY, "hello")
        check(rc2 == 0 and "OK:[OLLEH]" in out2, "update-secret: old entry runs NEW satellite",
              repr(out2.strip()))
    finally:
        shutil.rmtree(tmp_src, ignore_errors=True)
        shutil.rmtree(tmp_dist, ignore_errors=True)

    # rebuild a clean dist for the tamper / trace / foreign checks (the swap above mutated it)
    _build(SRC, DIST)

    # 6. traced load -> decoy (real output gone). Done before the destructive tamper checks.
    tout = _run_traced(ENTRY, KEY, "hello")
    check("OK:OLLEH" not in tout, "tamper: tracer at load -> decoy", repr(tout.strip()[:60]))

    # 7. foreign import of a satellite WITHOUT the entry -> fail (entry-bound, D7)
    fout = _foreign_import(DIST, "app.secret")
    check("FAILED" in fout and "LOADED" not in fout, "tamper: foreign import -> fail", repr(fout.strip()))

    # 4. tamper the ENTRY -> genuine output gone
    _corrupt_blobs(ENTRY)
    out4, _ = _run(ENTRY, KEY, "hello")
    check("OK:OLLEH" not in out4, "tamper: corrupt entry -> broken", repr(out4.strip()[:60]))

    # 5. tamper a SATELLITE -> that module breaks (rebuild clean first)
    _build(SRC, DIST)
    _corrupt_blobs(SECRET)
    out5, _ = _run(ENTRY, KEY, "hello")
    check("OK:OLLEH" not in out5, "tamper: corrupt satellite -> broken", repr(out5.strip()[:60]))

    # static: the protected logic must not be plaintext in the shipped satellite
    _build(SRC, DIST)
    sat_src = open(SECRET, encoding="utf-8").read()
    no_plain = ("PYOBF-PRO-2026" not in sat_src and "core_transform" not in sat_src
                and "[::-1]" not in sat_src)
    check(no_plain, "static: protected logic absent from satellite source")

    if fails:
        print("\n!!! PROJECT BUILD VERIFICATION FAILED:", fails)
        return 1

    # analyze deliverables (debug visualizations; emitted only after verification passes)
    _emit_analysis()

    print("\nBUILD OK. dist/ written (git-ignored): main.py + app/{__init__,logic}.py + "
          "app/secret.py (stub+blob).")
    return 0


if __name__ == "__main__":
    import argparse

    _p = argparse.ArgumentParser(description="Build + self-verify the multi-module demo.")
    _p.add_argument("--key", default=KEY,
                    help="license key injected at build time via precompile_arg('LICENSE_KEY') "
                         "(default: %(default)s). The key is folded into the encrypted body and never "
                         "appears in the shipped source.")
    KEY = _p.parse_args().key   # build-time injection driven by the CLI (the CI/build supplies the secret)
    raise SystemExit(main())
