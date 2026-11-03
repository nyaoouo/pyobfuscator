"""Use the shared paired call workload to isolate typed-frame costs."""

from measure_cff_references import main


if __name__ == "__main__":
    main(recipes={"plain": {}, "cfg": {}, "call-frames": {"call-frames": "required"},
                  "frames-and-references": {"call-frames": "required", "reference-routes": "required"}},
         comparison="same-source/seed plain, CFG-only, typed owned frames and frames plus reference tables")
