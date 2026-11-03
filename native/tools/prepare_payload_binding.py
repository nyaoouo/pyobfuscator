"""Prepare strict payload recipe/reference inputs before its native compilation."""
import argparse
import json
from pathlib import Path
import re

from atomic_artifact import atomic_write
from payload_binding import binding_recipe, private_reference, render_post_profile
from post_mixed_binding import mixed_private_reference, render_post_mixed_sites
from prepare_scope_material import read_material
from release_material import _unique, parse_material


def main():
    parser = argparse.ArgumentParser()
    for name in ("material", "config_header", "recipe_output", "reference_output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--scope-material", type=Path)
    parser.add_argument("--post-profile", type=Path)
    parser.add_argument("--phase", choices=("all", "early", "late"), default="all")
    parser.add_argument("--mixed", action="store_true")
    parser.add_argument("--mixed-plan", type=Path)
    parser.add_argument("--mixed-header", type=Path)
    args = parser.parse_args()
    if bool(args.scope_material) != bool(args.post_profile): parser.error("measured binding requires material and profile paths")
    if args.mixed and not args.scope_material: parser.error("mixed binding requires measured POST material")
    if bool(args.mixed_plan) != (args.mixed and args.phase == "late") or bool(args.mixed_header) != bool(args.mixed_plan):
        parser.error("mixed POST needs a frozen plan and site header only in the late phase")
    paths = [args.material, args.config_header, args.recipe_output, args.reference_output]
    if args.recipe: paths.append(args.recipe)
    if args.scope_material: paths.extend((args.scope_material, args.post_profile))
    if args.mixed_plan: paths.append(args.mixed_plan)
    if args.mixed_header: paths.append(args.mixed_header)
    if len({path.resolve() for path in paths}) != len(paths):
        parser.error("payload binding inputs and outputs must have distinct paths")
    try:
        material = parse_material(args.material.read_bytes())
        header = args.config_header.read_text(encoding="ascii")
        routes = re.findall(r"(?m)^#define PYOBF_DEMO_ENV_OPERATION_ID ([0-9]+)u$", header)
        if len(routes) != 1: raise ValueError("payload binding configuration has no unique routing tag")
        configuration = json.loads(args.recipe.read_bytes(), object_pairs_hook=_unique) if args.recipe else {"schema_version": 1}
        scoped = read_material(args.scope_material) if args.scope_material else None
        recipe = binding_recipe(configuration, measured=scoped is not None, mixed=args.mixed)
        early_reference = private_reference(material, int(routes[0]), scoped_material=scoped)
        if args.phase != "late":
            if args.post_profile: atomic_write(args.post_profile, render_post_profile(early_reference).encode("ascii"))
            atomic_write(args.recipe_output, (json.dumps(recipe, indent=2, sort_keys=True) + "\n").encode())
        if args.phase != "early":
            reference = (mixed_private_reference(material, int(routes[0]), scoped, args.mixed_plan.read_bytes())
                         if args.mixed else early_reference)
            if args.mixed_header:
                atomic_write(args.mixed_header, render_post_mixed_sites(reference).encode("ascii"))
            atomic_write(args.reference_output, (json.dumps(reference, indent=2, sort_keys=True) + "\n").encode())
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
