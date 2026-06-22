import argparse
from pyobfuscator import local_call  # no-op marker; obfuscator renames/inlines + strips it
# flag = "{ctf-owoQwQ>w<=w=^o^uwu}"   (ASCII kaomoji; 6 segments x 4 chars)
#
# This is a SHOWCASE challenge: each 4-char segment is validated by a check that exercises a
# DIFFERENT Python construct the obfuscator supports, so the obfuscated artifact demonstrates the
# full flattening surface (class / property / classmethod / super / with / try-finally / match /
# assert / comprehension / walrus / zip / enumerate / for-else). Difficulty is intentionally modest.
# Every segment check pins each of its 4 characters by a per-character INVERTIBLE relation
# (divmod / per-char code list / xor keystream / exact match), so the flag is the UNIQUE accepted answer.


# --- segment 0: class + @property + @classmethod + super() -------------------------------------
class _Verifier:
    """Base verifier — holds a segment, exposes its code points, and a shape check that subclasses
    extend via super()."""
    def __init__(self, seg):
        self.seg = seg

    @property
    def codes(self):
        return [ord(c) for c in self.seg]

    @classmethod
    def of(cls, seg):
        return cls(seg)

    def ok(self):
        return len(self.seg) == 4            # base: shape only


class _Q0(_Verifier):
    _SPEC = ((7, 17, 4), (5, 19, 4), (3, 38, 2), (42, 2, 18))   # per-char (a, n//a, n%a)

    def ok(self):
        if not super().ok():                 # super() -> base shape check
            return False
        for n, (a, b, c) in zip(self.codes, self._SPEC):
            if n // a != b or n % a != c:
                return False
        return True


@local_call
def check0(seg):
    return _Q0.of(seg).ok()


# --- segment 1: with (context manager) ---------------------------------------------------------
class _Accum:
    # Accumulates a running total AND a per-position transformed code list. The code list is what
    # makes the segment UNIQUELY solvable: enc[i] = 3*ord + i is strictly increasing in ord, so a
    # given code has exactly one preimage char (invert: ord = (enc - i) // 3). total is a redundant
    # cross-check.
    def __init__(self):
        self.total = 0
        self.codes = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def add(self, i, n):
        self.total += n
        self.codes.append(3 * n + i)


@local_call
def check1(seg):
    if len(seg) != 4:
        return False
    with _Accum() as acc:
        for i, ch in enumerate(seg):
            acc.add(i, ord(ch))
    return acc.codes == [135, 334, 359, 336] and acc.total == 386


# --- segment 2: try / finally (cleanup always runs) --------------------------------------------
@local_call
def check2(seg):
    # per-char xor keystream ks(i)=(i*53+17)&0xFF -> a bijection, so each code has exactly one
    # preimage char (invert: ord = code ^ ks(i)). Unique.
    probe = []
    try:
        if len(seg) != 4:
            return False
        for i, ch in enumerate(seg):
            probe.append(ord(ch) ^ ((i * 53 + 17) & 0xFF))
        return probe == [64, 49, 42, 142]
    finally:
        probe.clear()                            # finally cleanup (showcase)


# --- segment 3: match statement (value / OR / guard / wildcard patterns) -----------------------
@local_call
def check3(seg):
    if len(seg) != 4:
        return False
    ok = True
    for i, ch in enumerate(seg):
        n = ord(ch)
        match i:
            case 0 | 3:                  # MatchOr of MatchValue
                ok = ok and n == 119     # 'w'
            case 1:
                ok = ok and n == 60      # '<'
            case _ if n == 61:           # wildcard + guard -> '='
                ok = ok and True
            case _:
                ok = False
    return ok


# --- segment 4: assert + comprehension + generator expr ----------------------------------------
@local_call
def check4(seg):
    if len(seg) != 4:
        return False
    v = [ord(ch) for ch in seg]
    try:
        # per-char affine enc = 5*ord + 2*i (strictly increasing -> one preimage per code): UNIQUE.
        assert [5 * n + 2 * i for i, n in enumerate(v)] == [305, 472, 559, 476]
        assert sum(n * n for n in v) == 33714      # redundant sum-of-squares cross-check (genexpr)
    except AssertionError:
        return False
    return True


# --- segment 5: walrus + zip + for/else --------------------------------------------------------
_SPEC5 = ((10, 11, 7), (10, 11, 9), (10, 11, 7), (10, 12, 5))   # per-char (a, n//a, n%a)


@local_call
def check5(seg):
    if len(seg) != 4:
        return False
    codes = [ord(c) for c in seg]
    if (total := sum(codes)) != 478:        # walrus
        return False
    for n, (a, b, c) in zip(codes, _SPEC5):
        if n // a != b or n % a != c:
            break
    else:                                    # for/else: ran without break -> all matched
        return seg[0] == seg[2]              # 'u' == 'u'
    return False


@local_call
def test_key(key):
    print("%AntiAi%"[:0], end="")            # no-op anti-AI carrier (build-time marker substitution)
    segs = [key[i:i + 4] for i in range(0, len(key), 4)]
    if len(segs) != 6:
        return False
    checks = (check0, check1, check2, check3, check4, check5)
    return all(chk(seg) for chk, seg in zip(checks, segs))


@local_call
def _main():
    s = input("Enter the flag: ")
    if test_key(s):
        print("Correct!")
    else:
        print("Wrong!")


def main():
    ap = argparse.ArgumentParser()
    # ctf_test.py {key} -> exit(0) if correct, exit(1) if wrong
    # ctf_test.py -> run the interactive test
    ap.add_argument("key", nargs="?", help="the flag to test")
    args = ap.parse_args()
    if args.key is not None:
        if test_key(args.key):
            print("Correct!")
            exit(0)
        else:
            print("Wrong!")
            exit(1)
    else:
        _main()


if __name__ == "__main__":
    main()
