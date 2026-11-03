"""Valid-IR marker boundary and post-emission dataflow mutations."""

import re

MARKER = "pyobf_native_path_fold_init_v1"
DECL = f"declare void @{MARKER}(ptr, i32) nounwind\n"
CALL = f"call void @{MARKER}(ptr nonnull align 4 dereferenceable(32) %storage, i32 123) nounwind"

PAD_HARNESS = r'''
#include "path_fold/marker.hpp"
#include <cstdio>
static bool throwing;
extern "C" void may_throw() { if (throwing) throw 29u; }
extern "C" void probe(pyobfuscator::native::path_fold::Storage &, unsigned);
int main() {
    for (unsigned mode = 0; mode != 2; ++mode) {
        pyobfuscator::native::path_fold::Storage storage;
        throwing = mode != 0;
        bool caught = false;
        try { probe(storage, 0); }
        catch (unsigned value) { if (value != 29) return 1; caught = true; }
        if (caught != throwing) return 2;
        std::printf("%u", mode);
        for (auto word : storage.words) std::printf(" %u", word);
        std::puts("");
    }
}
'''


def body(call=CALL, declaration=DECL, extra=""):
    return declaration + extra + "\ndefine void @probe(ptr %storage, i32 %word) {\nentry:\n  " + call + "\n  ret void\n}\n"


def rejected_markers():
    return [
        ("dynamic", body(CALL.replace("i32 123", "i32 %word")), "fixed i32"),
        ("wide", body(CALL.replace("i32 123", "i64 123"), DECL.replace("i32", "i64")), "fixed i32"),
        ("throwing", body(CALL.replace(" nounwind", ""), DECL.replace(" nounwind", "")), "direct nounwind"),
        ("weak", body(declaration=DECL.replace("declare void", "declare extern_weak void")), "exact v1 ABI"),
        ("defined", body(declaration=f"define void @{MARKER}(ptr %s, i32 %x) nounwind {{ ret void }}\n"), "marker declaration"),
        ("escaped", body(extra=f"@escaped = global ptr @{MARKER}\n"), "address escapes"),
        ("alignment", body(CALL.replace("align 4", "align 2")), "aligned eight-word"),
        ("span", body(CALL.replace("dereferenceable(32)", "dereferenceable(16)")), "aligned eight-word"),
        ("null", body(CALL.replace("%storage, i32 123", "null, i32 123")), "aligned eight-word"),
        ("poison", body(CALL.replace("%storage, i32 123", "poison, i32 123")), "aligned eight-word"),
        ("musttail", body("musttail " + CALL), "exact v1 ABI"),
        ("convention", body(CALL.replace("call void", "call fastcc void"), DECL.replace("declare void", "declare fastcc void")), "exact v1 ABI"),
        ("bundle", body(CALL + ' ["deopt"(i32 1)]'), "exact v1 ABI"),
        ("byval", body(CALL.replace("ptr nonnull", "ptr byval([8 x i32]) nonnull"),
                       DECL.replace("(ptr,", "(ptr byval([8 x i32]),")), "ordinary v1 reference ABI"),
        ("sret", body(CALL.replace("ptr nonnull", "ptr sret([8 x i32]) nonnull"),
                      DECL.replace("(ptr,", "(ptr sret([8 x i32]),")), "ordinary v1 reference ABI"),
        ("eh-pad", 'target triple = "x86_64-w64-windows-gnu"\n' + DECL + "declare void @may_throw()\ndeclare i32 @__gxx_personality_seh0(...)\n"
            "define void @probe(ptr %storage, i32 %word) personality ptr @__gxx_personality_seh0 {\n"
            "entry:\n  invoke void @may_throw() to label %done unwind label %handler\n"
            "handler:\n  %landing = landingpad { ptr, i32 } cleanup\n  " + CALL +
            "\n  resume { ptr, i32 } %landing\ndone:\n  ret void\n}\n", "not EH pad headers"),
        ("zero", "define void @probe(ptr %storage, i32 %word) { ret void }\n", "zero eligible required sites"),
    ]


def guard_mutations(source):
    lines = source.splitlines(keepends=True)
    store = next(index for index, line in enumerate(lines) if "store volatile i32" in line and "!pyobf.path-fold.bound" in line)
    current = next(index for index, line in enumerate(lines) if "load volatile i32" in line and "!pyobf.path-fold.state" in line)
    before = next(index for index, line in enumerate(lines) if "load volatile i32" in line and "!pyobf.path-fold.before" in line)
    changed = list(lines); changed.pop(store)
    yield "missing-store", "".join(changed)
    changed = list(lines); changed[store] = re.sub(r"store volatile i32 [^,]+,", "store volatile i32 0,", changed[store], count=1)
    yield "constant-output", "".join(changed)
    changed = list(lines); changed[store] = re.sub(r"ptr [^,]+,", "ptr null,", changed[store], count=1)
    yield "foreign-span", "".join(changed)
    for name, index in (("current-nonvolatile", current), ("snapshot-nonvolatile", before)):
        changed = list(lines); changed[index] = changed[index].replace("load volatile", "load", 1)
        yield name, "".join(changed)
    changed = list(lines)
    changed[current] = re.sub(r", !pyobf\.path-fold\.state !\d+", "", changed[current], count=1)
    yield "missing-owner", "".join(changed)
    yield "missing-binding", source.replace('"pyobf.path-fold.bound"', "", 1)
    for index in range(current + 1, len(lines)):
        if " = xor i32 %pyobf.fold.state" in lines[index]:
            changed = list(lines)
            changed[index] = re.sub(r"(, )(-?\d+)", lambda match: match[1] + str(int(match[2]) ^ 1), changed[index], count=1)
            yield "wrong-current-word", "".join(changed)
            break
    for index in range(current + 1, len(lines)):
        if " = mul i32 " in lines[index]:
            changed = list(lines); changed[index] = changed[index].replace("mul i32", "mul nuw i32", 1)
            yield "poison-arithmetic", "".join(changed)
            break
