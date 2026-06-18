"""lift_lambdas: every liftable lambda becomes a named def, behaviour preserved."""
import ast

from pyobfuscator.cff.lambdalift import lift_lambdas


def _run(src):
    ns = {}
    exec(compile(ast.parse(src), "<t>", "exec"), ns)
    return ns


def _lift(src):
    tree = ast.parse(src)
    lift_lambdas(tree)
    out = ast.unparse(tree)
    assert "lambda" not in out, f"lambda remains:\n{out}"
    return out


def test_simple_assignment():
    out = _lift("f = lambda x: x + 1\nr = f(10)\n")
    assert _run(out)["r"] == 11


def test_in_call_arg_setdefault():
    out = _lift("d = {}\nv = d.setdefault('k', lambda s: s * 2)\nr = v(21)\n")
    assert _run(out)["r"] == 42


def test_nested_lambda_closure():
    out = _lift("adder = lambda a: lambda b: a + b\nr = adder(3)(4)\n")
    assert _run(out)["r"] == 7


def test_closure_over_enclosing_local():
    out = _lift("def make(n):\n    return lambda x: x + n\ng = make(100)\nr = g(5)\n")
    assert _run(out)["r"] == 105


def test_default_arg_lambda():
    out = _lift("def f(cb=lambda: 7):\n    return cb()\nr = f()\n")
    assert _run(out)["r"] == 7


def test_multiple_lambdas_one_statement():
    out = _lift("pair = (lambda: 1, lambda: 2)\nr = pair[0]() + pair[1]()\n")
    assert _run(out)["r"] == 3


def test_map_filter_behavior():
    out = _lift("nums=[1,2,3,4]\nr=list(map(lambda x: x*x, filter(lambda x: x%2==0, nums)))\n")
    assert _run(out)["r"] == [4, 16]


def test_lambda_inside_comprehension_left_alone():
    # Lifting out of a comprehension's own scope would change free-var resolution; leave it.
    tree = ast.parse("fns = [(lambda x: x + i) for i in range(3)]\n")
    lift_lambdas(tree)
    assert any(isinstance(n, ast.Lambda) for n in ast.walk(tree))


def test_idempotent():
    tree = ast.parse("f = lambda x: x\n")
    lift_lambdas(tree)
    n1 = sum(isinstance(n, ast.FunctionDef) for n in ast.walk(tree))
    lift_lambdas(tree)
    n2 = sum(isinstance(n, ast.FunctionDef) for n in ast.walk(tree))
    assert n1 == n2 == 1


def test_attest_style_nested_oracle():
    # mirrors a nested-lambda closure shape: (lambda k, m: lambda s: (s ^ k ^ m) & 0xFF)(a, b)
    src = ("g = {}\n"
           "g['o'] = (lambda k, m: lambda s: (s ^ k ^ m) & 255)(7, 9)\n"
           "r = g['o'](100)\n")
    out = _lift(src)
    assert _run(out)["r"] == ((100 ^ 7 ^ 9) & 255)
