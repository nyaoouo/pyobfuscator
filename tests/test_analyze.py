import json

import pytest

from pyobfuscator import build_model, analyze_html
from pyobfuscator.options import ObfOptions

LOOP = (
    "def f(items):\n"
    "    total = 0\n"
    "    for x in items:\n"
    "        if x > 0:\n"
    "            total += x\n"
    "    return total\n"
)


def test_model_basic_shape():
    m = build_model(LOOP)
    assert m["schema"] == 1
    assert len(m["scopes"]) == 1
    sc = m["scopes"][0]
    assert sc["name"] == "f" and sc["qualname"] == "f"
    assert sc["supported"] is True
    assert isinstance(sc["entry"], int)
    assert len(sc["blocks"]) >= 4  # entry + loop head + body + after, at least
    # term kinds we expect to appear
    kinds = {b["term"]["kind"] for b in sc["blocks"]}
    assert "cond" in kinds and "ret" in kinds and "goto" in kinds


def test_model_source_mapping_lines_are_real():
    m = build_model(LOOP)
    sc = m["scopes"][0]
    # source_lines cover the function (lines 1..6)
    nums = [sl["n"] for sl in sc["source_lines"]]
    assert nums == [1, 2, 3, 4, 5, 6]
    # at least one block maps to the `total += x` line (line 5)
    assert any(b["lines"] and b["lines"][0] <= 5 <= b["lines"][1] for b in sc["blocks"])
    # a block exists that maps to line 2 (total = 0)
    assert any(b["lines"] and b["lines"][0] <= 2 <= b["lines"][1] for b in sc["blocks"])


def test_block_flat_lines_point_at_their_guard_in_output():
    m = build_model(LOOP)
    sc = m["scopes"][0]
    assert sc.get("flattened_lines")
    flat = [fl["text"] for fl in sc["flattened_lines"]]
    for b in sc["blocks"]:
        assert b["flat_lines"], f"block {b['id']} has no output mapping"
        guard_line = flat[b["flat_lines"][0] - 1]
        assert ("== " + str(b["id"]) + ":") in guard_line


def test_nested_functions_become_two_scopes():
    src = (
        "def outer(n):\n"
        "    def inner(x):\n"
        "        return x + n\n"
        "    return inner(n)\n"
    )
    m = build_model(src)
    quals = {sc["qualname"] for sc in m["scopes"]}
    assert quals == {"outer", "outer.inner"}


def test_unsupported_scope_is_reported_not_crashed():
    # `global` is not in the cfg lowerer — it raises AssertionError → supported:False
    src = "def f():\n    global x\n    x = 1\n"
    m = build_model(src)
    sc = m["scopes"][0]
    assert sc["supported"] is False
    assert "reason" in sc and sc["reason"]


def test_seed_is_deterministic_in_model():
    a = build_model(LOOP, ObfOptions(seed=5))
    b = build_model(LOOP, ObfOptions(seed=5))
    assert a == b


def test_analyze_html_is_self_contained_and_data_roundtrips():
    html = analyze_html(LOOP)
    # inlined renderer + css present (no external src/link)
    assert "global.PYOBF = { render }" in html or "global.PYOBF=" in html or "PYOBF" in html
    assert "<script src=" not in html and "<link " not in html
    assert "window.__PYOBF__ =" in html
    # extract the embedded JSON and verify it parses + matches build_model
    start = html.index("window.__PYOBF__ =") + len("window.__PYOBF__ =")
    end = html.index("PYOBF.render(", start)
    blob = html[start:end].strip().rstrip(";").strip()
    blob = blob.replace("<\\/", "</")  # undo the <script>-safety escaping
    data = json.loads(blob)
    assert data["scopes"][0]["qualname"] == "f"


def test_analyze_html_escapes_closing_script_in_strings():
    # a string literal containing </script> must not break out of the <script> tag
    src = "def f():\n    return '</script>'\n"
    html = analyze_html(src)
    start = html.index("window.__PYOBF__ =") + len("window.__PYOBF__ =")
    end = html.index("PYOBF.render(", start)
    blob = html[start:end].strip().rstrip(";").strip()
    assert "</script>" not in blob          # raw closer must not appear in the data
    assert "<\\/script>" in blob            # it is escaped
    assert json.loads(blob.replace("<\\/", "</"))  # still valid JSON


def test_trivial_scope_marked_not_flattened():
    src = "def f(x):\n    return x + 1\n"  # single block
    sc = build_model(src)["scopes"][0]
    assert sc["supported"] is True and sc["flattened"] is False
    assert "skip_reason" in sc
    assert "while True" not in "\n".join(fl["text"] for fl in sc["flattened_lines"])


def test_try_except_scope_has_handler_dispatch_and_raise_kinds():
    src = ("def f(a, b):\n"
           "    try:\n"
           "        return a // b\n"
           "    except ZeroDivisionError:\n"
           "        raise RuntimeError('x')\n")
    sc = build_model(src)["scopes"][0]
    assert sc["supported"] and sc["flattened"]
    kinds = {b["term"]["kind"] for b in sc["blocks"]}
    assert "handler_dispatch" in kinds and "raise" in kinds
    # html still assembles
    from pyobfuscator import analyze_html
    assert "window.__PYOBF__ =" in analyze_html(src)


def test_finally_scope_builds_and_html_assembles():
    src = ("def f(x):\n    try:\n        return 10 // x\n    finally:\n        print('f')\n")
    from pyobfuscator import build_model, analyze_html, ObfOptions
    sc = build_model(src, ObfOptions(min_blocks=1))["scopes"][0]
    assert sc["supported"] is True and sc["flattened"] is True
    assert "window.__PYOBF__ =" in analyze_html(src, ObfOptions(min_blocks=1))


def test_break_across_finally_marked_unsupported():
    src = ("def f(n):\n    for i in range(n):\n        try:\n            if i == 2:\n"
           "                break\n            print(i)\n        finally:\n            print('f')\n")
    from pyobfuscator import build_model
    sc = build_model(src)["scopes"][0]
    assert sc["supported"] is False
    assert "break" in sc["reason"].lower() or "finally" in sc["reason"].lower()


# ---- pass timeline (per-plugin snapshots) --------------------------------
def test_passes_timeline_starts_original_ends_flatten():
    p = build_model(LOOP)["passes"]
    assert p[0]["name"] == "original" and p[0]["changed"] == []
    assert p[-1]["name"] == "flatten" and p[-1].get("has_cfg") is True
    # only-changed invariant: no two consecutive shown steps share identical source
    texts = ["\n".join(l["text"] for l in s["lines"]) for s in p if "lines" in s]
    assert all(texts[i] != texts[i + 1] for i in range(len(texts) - 1))


def test_passes_changed_lines_in_bounds():
    for s in build_model(LOOP)["passes"]:
        if "lines" in s:
            n = len(s["lines"])
            assert all(1 <= c <= n for c in s["changed"])


def test_passes_inactive_collapsed():
    # slot_vars is off by default -> SlotVarPass changed nothing -> no 'slotvar' step
    assert "slotvar" not in [s["name"] for s in build_model(LOOP)["passes"]]


def test_schema_still_1_and_scopes_intact():
    m = build_model(LOOP)
    assert m["schema"] == 1 and m["scopes"][0]["qualname"] == "f"


def test_passes_deterministic_under_seed():
    assert build_model(LOOP, ObfOptions(seed=7)) == build_model(LOOP, ObfOptions(seed=7))


def test_passes_not_hardcoded_follows_live_pipeline(monkeypatch):
    # If the live pipeline is swapped out, the timeline FOLLOWS it (no hardcoded order/list).
    import pyobfuscator
    import pyobfuscator.cff.passes.base as base
    from pyobfuscator.cff.passes.dataobf import DataObfPass
    monkeypatch.setattr(pyobfuscator, "_MODULE_PIPELINE", base.Pipeline([DataObfPass()]))
    names = [s["name"] for s in build_model(LOOP)["passes"]]
    assert names[0] == "original" and "flatten" not in names  # flatten no longer in the pipeline


def test_analyze_html_embeds_timeline_markup():
    html = analyze_html(LOOP)
    assert "renderTimeline" in html  # shared renderer present
    # the embedded data carries the passes array
    start = html.index("window.__PYOBF__ =") + len("window.__PYOBF__ =")
    end = html.index("PYOBF.render(", start)
    blob = html[start:end].strip().rstrip(";").strip().replace("<\\/", "</")
    assert json.loads(blob)["passes"][0]["name"] == "original"


# ---- protect shell visualizer (no-core part) -----------------------------
_PSRC = "def add(a, b):\n    s = a + b\n    return s\n\nfor i in range(10):\n    print(add(i, i))\n"


def test_protect_model_layers():
    from pyobfuscator.cff.analyze import build_protect_model
    from pyobfuscator.options import ModuleObfOptions, OutputFormat
    m = build_protect_model(_PSRC, ModuleObfOptions(seed=9, output=OutputFormat.TEXT))
    assert m["schema"] == 1 and m["format"] in ("source", "bytecode")
    assert [l["name"] for l in m["layers"]] == ["serialize", "zlib", "encrypt", "encode", "launcher"]
    by = {l["name"]: l for l in m["layers"]}
    assert by["zlib"]["bytes"] < by["serialize"]["bytes"]      # compression helped
    assert by["encrypt"]["bytes"] == by["zlib"]["bytes"]        # XOR is length-preserving
    assert m["launcher_source"]


def test_protect_model_text_b85_vs_pyc_raw_encode():
    from pyobfuscator.cff.analyze import build_protect_model
    from pyobfuscator.options import ModuleObfOptions, OutputFormat
    t = {l["name"]: l for l in build_protect_model(_PSRC, ModuleObfOptions(seed=9, output=OutputFormat.TEXT))["layers"]}
    p = {l["name"]: l for l in build_protect_model(_PSRC, ModuleObfOptions(seed=9, output=OutputFormat.PYC))["layers"]}
    assert t["encode"]["bytes"] > t["zlib"]["bytes"]    # b85 inflates
    assert p["encode"]["bytes"] == p["zlib"]["bytes"]   # pyc embeds raw bytes


def test_protect_html_self_contained():
    from pyobfuscator.cff.analyze import protect_html
    from pyobfuscator.options import ModuleObfOptions, OutputFormat
    html = protect_html("x = 1\nprint(x)\n", ModuleObfOptions(seed=1, output=OutputFormat.TEXT))
    assert "<script src=" not in html and "<link " not in html
    assert "window.__PYOBF_PROTECT__ =" in html and "PYOBF.renderProtect(" in html
    assert "renderLayers" in html or "renderProtect" in html


def test_protect_model_deterministic():
    from pyobfuscator.cff.analyze import build_protect_model
    from pyobfuscator.options import ModuleObfOptions, OutputFormat
    mk = lambda: ModuleObfOptions(seed=4, output=OutputFormat.TEXT)
    assert build_protect_model(_PSRC, mk()) == build_protect_model(_PSRC, mk())
