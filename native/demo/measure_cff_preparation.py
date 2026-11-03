"""Measure preparation against the same plain, CFG-only and typed-frame workload."""

from measure_cff_references import main


if __name__ == "__main__":
    main(recipes={"plain": {}, "cfg": {}, "call-frames": {"call-frames": "required"},
                  "call-preparation": {"call-frames": "required", "call-preparation": "required"},
                  "preparation-and-references": {"call-frames": "required", "call-preparation": "required", "reference-routes": "required"}},
         comparison="same-source/seed plain, CFG-only, typed frames, cross-state preparation and reference composition")
