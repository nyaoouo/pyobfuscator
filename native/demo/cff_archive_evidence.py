"""Scoped linked x86 evidence for archive state-key lanes, separate from source coverage."""

import re


def check_archive_evidence(row: dict, code: str) -> None:
    component = next((item for item in row.get('components', []) if item['component'] == 'constant-archive'), {})
    if not component.get('applied'):
        return
    lanes = component.get('applied_types', {}).get('key-word32', 0)
    sources = row.get('archive_sources', {})
    acquisitions = sources.get('acquisitions', 0)
    if (not acquisitions or lanes != acquisitions * 8 or component['applied'] != acquisitions * 9 or
            sources.get('complete_acquisitions') != acquisitions):
        raise SystemExit(f'archive source/lane evidence is incomplete: {row["function"]}')
    if len(re.findall(r'\bimull\s+\$0xc2b2ae35\b', code)) < lanes:
        raise SystemExit(f'linked DLL lost state-dependent archive keys: {row["function"]}')
