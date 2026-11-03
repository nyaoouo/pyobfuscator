"""Measure imported-address routing against one fixed separately linked provider."""

from measure_cff_references import main
from measure_cff_external import SOURCE_IR, PROVIDER_IR


if __name__ == "__main__":
    main(source_ir=SOURCE_IR, provider_ir=PROVIDER_IR,
        recipes={"plain": {}, "cfg": {}, "import-routes": {"import-routes": "required"},
                 "imported-frames": {"import-routes": "required", "external-calls": "required", "reference-routes": "required"},
                 "imported-preparation": {"import-routes": "required", "external-calls": "required", "reference-routes": "required", "call-preparation": "required"}},
        comparison="same-source/seed and unchanged provider DLL: plain, CFG-only, imported routes, external frames and state-bound preparation")
