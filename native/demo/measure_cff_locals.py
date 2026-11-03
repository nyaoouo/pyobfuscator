"""Isolate indexed-local costs while preserving real memory objects before ordinary O2."""

from measure_cff_references import main, SOURCE_IR as CALL_IR


SOURCE_IR = CALL_IR.replace('entry:\n  %a = call i32 @scale(i32 %x)', '''entry:
  %left = alloca i32, align 16
  %right = alloca i32, align 16
  store volatile i32 %x, ptr %left, align 16
  %input = load volatile i32, ptr %left, align 16
  %a = call i32 @scale(i32 %input)
  store volatile i32 %a, ptr %right, align 16
  %saved = load volatile i32, ptr %right, align 16''').replace(
    '%b = call i32 @adjust(i32 %a)', '%b = call i32 @adjust(i32 %saved)')


if __name__ == "__main__":
    main(source_ir=SOURCE_IR, recipes={"plain": {}, "cfg": {}, "indexed-locals": {"indexed-locals": "required"},
        "locals-and-calls": {"indexed-locals": "required", "call-frames": "required", "call-preparation": "required", "reference-routes": "required"}},
        comparison="same-source/seed volatile typed objects: plain, CFG-only, indexed locals and call/preparation/reference composition")
