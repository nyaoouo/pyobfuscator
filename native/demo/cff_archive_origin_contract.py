"""Exact build-input roles for the selected G3 archive-origin proof."""

from pathlib import Path


ROLES = (
    "optimized_ir", "archive_plan", "pending_ir", "package",
    "generated_cpp", "bindings", "source_requests", "runtime_requested_ir",
    "runtime_requests", "merged_requests", "linked_ir", "prepared_ir",
    "recipe", "opt_exe", "llvm_link_exe", "pass_plugin",
    "pack_tool_source", "archive_format_source", "merge_requests_source",
    "child_replay_record",
)


def role_paths(values: list[str]) -> dict[str, Path]:
    """Parse one absolute path per role without silently replacing duplicates."""
    result = {}
    for value in values:
        if "=" not in value:
            raise ValueError("archive origin role needs name=path")
        name, raw_path = value.split("=", 1)
        path = Path(raw_path)
        if name in result or name not in ROLES or not raw_path or not path.is_absolute():
            raise ValueError("archive origin role is duplicate, unknown or not absolute")
        result[name] = path.resolve()
    if set(result) != set(ROLES):
        raise ValueError("archive origin needs every exact role")
    if len(set(result.values())) != len(result):
        raise ValueError("archive origin roles alias the same input")
    return result
