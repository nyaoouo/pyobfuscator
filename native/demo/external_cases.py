"""Separate-provider ABI, callback and effect fixtures for external typed adapters."""

import re

from frame_cases import SOURCE_IR as FRAME_IR, HARNESS, HELPER


FUNCTIONS = ("calls", "abi", "tail_call", "framed_reentrant", "framed_loop", "framed_values")
TARGETS = {"increment", "decrement", "touch", "floating", "fast", "aggregate",
           "pair_echo", "vector_echo", "nothing", "callback_adapter", "variadic_target"}
provider = []


def externalize(match: re.Match) -> str:
    header, body = match[1], match[2]
    name = re.search(r"@([\w.]+)\(", header)[1]
    if name not in TARGETS:
        return match[0]
    header = header.replace("internal ", "")
    provider.append("define " + header + " {" + body + "\n}\n")
    return "declare " + header + "\n"


SOURCE_IR = re.sub(r"^define ([^{}]+?) \{(.*?)\n\}", externalize, FRAME_IR, flags=re.M | re.S)
if len(provider) != len(TARGETS):
    raise AssertionError("external provider split lost an original function")
PROVIDER_IR = '''target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
%Pair = type { i32, double }
declare i32 @invoke_callback(ptr, i32)
''' + "\n".join(provider)
SOURCE_IR = SOURCE_IR.replace("%a = call i32 @touch(ptr %p, i32 %x)",
    "%same = call i32 @local_identity(i32 %x)\n  %a = call i32 @touch(ptr %p, i32 %same)") + '''
define internal i32 @local_identity(i32 %x) noinline { ret i32 %x }
declare i32 @pure_external(i32) memory(none) nounwind willreturn
define i32 @folded_external(i32 %x) noinline {
  %unused = call i32 @pure_external(i32 %x)
  ret i32 %x
}
'''
PROVIDER_IR += '\ndefine i32 @pure_external(i32 %x) { ret i32 %x }\n'

CPP_HEADER = '''#include <cstdint>
struct alignas(16) Sample { std::uint64_t number; double floating; };
extern "C" Sample typed_external(Sample, int) noexcept;
extern "C" int throwing_external(int);
'''
CPP_PROVIDER = CPP_HEADER + '''#include <stdexcept>
extern "C" __declspec(dllexport) Sample typed_external(Sample sample, int input) noexcept {
    sample.number += static_cast<std::uint64_t>(input); return sample;
}
extern "C" __declspec(dllexport) int throwing_external(int input) {
    if (input < 0) throw std::runtime_error("frame-unwind-token"); return input * 3;
}
'''
CPP_USER = CPP_HEADER + '''#include <cstring>
extern "C" __attribute__((noinline)) int frame_cpp_values(int input) noexcept {
    const Sample sample{31, -0.0}; const auto result = typed_external(sample, input);
    std::uint64_t bits; std::memcpy(&bits, &result.floating, sizeof(bits));
    return bits == 0x8000000000000000ull ? static_cast<int>(result.number) : -10000;
}
extern "C" __attribute__((noinline)) int frame_throwing_caller(int input) {
    return throwing_external(input) + 9;
}
'''
