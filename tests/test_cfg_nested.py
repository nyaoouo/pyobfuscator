import ast, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator.cff.cfg import flatten_function
from pyobfuscator.cff.names import Namer, collect_names


def _flatten_one(fn):
    namer = Namer(0, collect_names(fn))
    flatten_function(fn, namer)


def test_nested_def_kept_as_statement_and_runs():
    src = ("def outer(n):\n"
           "    def inner(x):\n"
           "        return x + n\n"
           "    return inner(10)\n")
    tree = ast.parse(src)
    outer = tree.body[0]
    # flatten ONLY the outer body; inner stays a normal (un-flattened) def statement
    _flatten_one(outer)
    ast.fix_missing_locations(tree)
    # the inner FunctionDef must still exist somewhere inside outer's new body
    inner_defs = [n for n in ast.walk(outer) if isinstance(n, ast.FunctionDef) and n is not outer]
    assert len(inner_defs) == 1 and inner_defs[0].name == "inner"
    ns = {}
    exec(compile(tree, "<n>", "exec"), ns)
    assert ns["outer"](5) == 15  # inner(10) = 10 + 5
