"""Public typed-data workload shared by all archive measurement variants."""

from __future__ import annotations

import re


DATA = b"native-archive-measurement\0\xff" + bytes(range(36))
assert len(DATA) == 64


def source_ir(target_ir: str) -> str:
    target = []
    for key in ("datalayout", "triple"):
        match = re.search(rf'^target {key} = "[^"]+"$', target_ir, re.MULTILINE)
        if match is None:
            raise ValueError(f"compiler probe did not declare a target {key}")
        target.append(match[0])
    encoded = "".join(f"\\{value:02X}" for value in DATA)
    return "\n".join(target) + f'''

@blob = private constant [64 x i8] c"{encoded}", align 16
@wide = private constant [3 x i16] [i16 55296, i16 90, i16 0], align 16
@number = private constant i33 8589934591, align 8
@nan = private constant double 0x7FF8123456789ABC, align 8
@negative_zero = private constant double 0x8000000000000000, align 8

define dllexport ptr @archive_pointer() {{
entry:
  ret ptr @blob
}}

define dllexport i32 @archive_compute(i32 %input) {{
entry:
  %index = and i32 %input, 31
  %offset = zext i32 %index to i64
  %address = getelementptr [64 x i8], ptr @blob, i64 0, i64 %offset
  %byte = load i8, ptr %address, align 1
  %word = load i16, ptr getelementptr ([3 x i16], ptr @wide, i64 0, i64 1), align 2
  %integer = load i33, ptr @number, align 8
  %floating = load double, ptr @nan, align 8
  %zero = load double, ptr @negative_zero, align 8
  %byte32 = zext i8 %byte to i32
  %word32 = zext i16 %word to i32
  %integer32 = trunc i33 %integer to i32
  %nanbits = bitcast double %floating to i64
  %nan32 = trunc i64 %nanbits to i32
  %zerobits = bitcast double %zero to i64
  %upper = lshr i64 %zerobits, 32
  %zero32 = trunc i64 %upper to i32
  %sum = add i32 %byte32, %word32
  %mix = xor i32 %sum, %integer32
  %mix2 = xor i32 %mix, %nan32
  %result = xor i32 %mix2, %zero32
  ret i32 %result
}}
'''
