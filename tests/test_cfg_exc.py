import ast, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator.cff.cfg import flatten_function
from pyobfuscator.cff.names import Namer, collect_names
from equivalence import assert_func_equivalent


def _flat(src, seed=0):
    tree = ast.parse(src)
    fn = tree.body[0]
    flatten_function(fn, Namer(seed, collect_names(fn)))
    ast.fix_missing_locations(tree)
    return tree, fn.name


def _check(src, name, batteries, seed=0):
    tree, fname = _flat(src, seed)
    def factory():
        ns = {}
        exec(compile(tree, "<exc>", "exec"), ns)
        return ns[fname]
    assert_func_equivalent(src, factory, name, batteries)


def test_basic_except():
    src = ("def f(a, b):\n"
           "    try:\n"
           "        return a // b\n"
           "    except ZeroDivisionError:\n"
           "        return -1\n")
    _check(src, "f", [((6, 2), {}), ((6, 0), {})])


def test_except_else():
    src = ("def f(x):\n"
           "    try:\n"
           "        y = int(x)\n"
           "    except ValueError:\n"
           "        return 'bad'\n"
           "    else:\n"
           "        return y * 2\n")
    _check(src, "f", [(("5",), {}), (("oops",), {})])


def test_multiple_handlers_and_as():
    src = ("def f(x):\n"
           "    try:\n"
           "        if x == 0:\n"
           "            raise ValueError('zero')\n"
           "        return 10 // x\n"
           "    except ZeroDivisionError:\n"
           "        return 'zde'\n"
           "    except ValueError as e:\n"
           "        return 'val:' + str(e)\n")
    _check(src, "f", [((0,), {}), ((2,), {})])


def test_nested_try_propagation():
    src = ("def f(x):\n"
           "    try:\n"
           "        try:\n"
           "            raise KeyError('k')\n"
           "        except ValueError:\n"
           "            return 'inner-val'\n"
           "    except KeyError:\n"
           "        return 'outer-key'\n")
    _check(src, "f", [((1,), {})])


def test_bare_reraise():
    src = ("def f(x):\n"
           "    try:\n"
           "        raise RuntimeError('boom')\n"
           "    except RuntimeError:\n"
           "        if x:\n"
           "            raise\n"
           "        return 'swallowed'\n")
    _check(src, "f", [((0,), {}), ((1,), {})])  # x=1 -> RuntimeError propagates


def test_uncaught_propagates_through_try():
    src = ("def f():\n"
           "    try:\n"
           "        raise KeyError('k')\n"
           "    except ValueError:\n"
           "        return 'nope'\n")
    _check(src, "f", [((), {})])  # KeyError must propagate (no matching handler)


def test_break_out_of_try_in_loop():
    src = ("def f(items):\n"
           "    seen = []\n"
           "    for x in items:\n"
           "        try:\n"
           "            seen.append(10 // x)\n"
           "        except ZeroDivisionError:\n"
           "            seen.append('z')\n"
           "        if len(seen) >= 3:\n"
           "            break\n"
           "    return seen\n")
    _check(src, "f", [(([1, 0, 2, 5, 4],), {}), (([1, 2],), {})])
