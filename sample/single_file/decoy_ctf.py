# Decoy CTF challenge — served by the protected launcher ONLY when tampering / dynamic analysis is
# detected (a debugger, sys.settrace, coverage, a foreign exec, ...). A reverse-engineer who traces the
# program to extract it lands HERE instead of the real challenge.
#
# Design:
#   * Traditional, BASIC reversing puzzle. The accepted flag NEVER appears as a literal anywhere; it is
#     verified through SEGMENTED, cross-checked arithmetic. Each 8-char block is pinned by a per-character
#     INVERTIBLE transform  enc[i] = mult*ord(c) + base + i  (mult > 0 -> strictly increasing in ord, so
#     every code has EXACTLY ONE preimage character; the analyst inverts ord = (enc - base - i) // mult).
#     On top of the per-char codes sit redundant segment / whole-inner cross-checks (sum + rolling
#     digest). Because every character is pinned independently, the puzzle has a UNIQUE solution and is
#     fully reversible — NOT a lossy checksum wall (sum / sum-of-squares / xor) that countless strings
#     satisfy.
#   * It is embedded with REDUCED obfuscation (build_ctf passes decoy_obf_overrides: no opaque
#     predicates / bogus blocks / junk / string-hiding; the obfuscator force-disables attestation for
#     the decoy so it runs under the very debugger that selected it). So once an analyst reaches it, the
#     puzzle is legible and solvable — and the flag they recover is self-mocking, making it obvious the
#     anti-debug fired and this is a TRAP. The flattened state machine and state-keyed integer consts
#     are kept, so it still reads as "an obfuscated program", just a tractable one.
#
# This file is a BUILD-WORKFLOW input (decoy_src). It is NOT part of the shipped pyobfuscator package,
# and is never executed on the genuine, untampered path. It keeps the real challenge's {ctf-...} shape.

import argparse


def _sum(s):
    return sum(ord(c) for c in s)


def _digest(s):
    acc = 0
    for c in s:
        acc = (acc * 131 + ord(c)) & 0xFFFFFFFF
    return acc


def _codes(s, mult, base):
    # per-character invertible transform: mult > 0 makes it strictly increasing in ord(c), so each
    # produced code has a single preimage character -> the block is UNIQUELY determined.
    return [mult * ord(c) + base + i for i, c in enumerate(s)]


def check_seg0(s):
    # leading block: per-char codes (mult 3) + a sum cross-check
    return _codes(s, 3, 7) == [355, 320, 324, 355, 230, 357, 247, 347] and _sum(s) == 817


def check_seg1(s):
    # middle block: per-char codes (mult 5) + an order-sensitive rolling-digest cross-check
    return _codes(s, 5, 11) == [591, 422, 518, 499, 555, 366, 557, 503] and _digest(s) == 3955233549


def check_seg2(s):
    # trailing block: per-char codes (mult 7) + a sum cross-check
    return _codes(s, 7, 3) == [724, 508, 684, 510, 686, 442, 842, 430] and _sum(s) == 682


def check_cross(inner):
    # whole-inner cross-validation tying the three blocks together: a rolling digest + total sum.
    return _digest(inner) == 2990563728 and _sum(inner) == 2278


def test_key(key):
    if not (key.startswith("{ctf-") and key.endswith("}")):
        return False
    inner = key[5:-1]
    if len(inner) != 24:
        return False
    a, b, c = inner[0:8], inner[8:16], inner[16:24]
    return (check_seg0(a) and check_seg1(b) and check_seg2(c)
            and check_cross(inner))


def main():
    ap = argparse.ArgumentParser(description="reverse the flag")
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
        s = input("Enter the flag: ")
        print("Correct!" if test_key(s) else "Wrong!")


if __name__ == "__main__":
    main()
