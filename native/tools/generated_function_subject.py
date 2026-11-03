"""Actual root plus registered generated helper bodies, without ordinary callee inference."""
from code_subject import Subject, validate_subject
from function_inventory import helpers
from function_subject import function_subject


def generated_function_subject(object_data, data, image, tag, name, ownership, *, aliases=(), fragments=()):
    root = function_subject(object_data, data, image, tag, name, aliases=aliases, fragments=fragments)
    ranges = list(root.ranges)
    for helper in helpers(object_data, ownership, name):
        # This producer admits whole noinline helper contributions. Unexpected helper
        # aliases/outlining refuse; friendly names do not supply a fragment contract.
        ranges.extend(function_subject(object_data, data, image, tag, helper).ranges)
    return validate_subject(image, Subject(tag, root.kind, root.label, tuple(sorted(ranges, key=lambda span: span.rva))))
