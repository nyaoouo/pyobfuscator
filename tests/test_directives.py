import ast
from pyobfuscator.cff.directives import Directive, extract_directives, map_to_defs

SRC = (
    "# pyobf: nocheck\n"
    "x = 1\n"
    "# pyobf: skip\n"
    "def f():\n"
    "    return 1\n"
    "def g():  # pyobf: level=heavy\n"
    "    return 2\n"
)


def test_extract_collects_pyobf_comments_only():
    ds = extract_directives(SRC)
    texts = [d.text for d in ds]
    assert texts == ["nocheck", "skip", "level=heavy"]


def test_extract_records_line_numbers():
    ds = extract_directives(SRC)
    assert ds[0].lineno == 1
    assert ds[1].lineno == 3
    assert ds[2].lineno == 6


def test_map_skip_to_following_def():
    ds = extract_directives(SRC)
    tree = ast.parse(SRC)
    mapping = map_to_defs(tree, ds)
    # the `skip` directive on line 3 binds to def f (line 4)
    skip = [d for d in ds if d.text == "skip"][0]
    assert mapping[skip] == "f"
    # the inline `level=heavy` on line 6 binds to def g (line 6)
    heavy = [d for d in ds if d.text == "level=heavy"][0]
    assert mapping[heavy] == "g"
