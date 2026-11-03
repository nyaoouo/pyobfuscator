"""Measure typed external frames against one fixed separate provider DLL."""

import re

from measure_cff_references import main, SOURCE_IR


PROVIDER_IR = 'target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n'
for match in re.finditer(r"define internal i32 @(scale|adjust)\(i32 %x\) noinline \{.*?\n\}", SOURCE_IR, re.S):
    PROVIDER_IR += match[0].replace("define internal", "define") + "\n"
SOURCE_IR = re.sub(r"define internal i32 @(scale|adjust)\(i32 %x\) noinline \{.*?\n\}",
                  lambda match: f"declare i32 @{match[1]}(i32)\n", SOURCE_IR, flags=re.S)


if __name__ == "__main__":
    main(source_ir=SOURCE_IR, provider_ir=PROVIDER_IR,
        recipes={"plain": {}, "cfg": {}, "external-calls": {"external-calls": "required"},
                 "external-preparation": {"external-calls": "required", "call-preparation": "required", "reference-routes": "required"}},
        comparison="same-source/seed and unchanged provider DLL: plain, CFG-only, external typed frames and state-bound preparation")
