"""Execute the real private-plan -> pack -> wrapper -> CFF -> DLL archive pipeline."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from archive_plan_cases import POSITIVE
from archive_protected_negative import check_failures


def run(command: list[str], *, succeeds: bool = True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f'protected archive command differs: {command}\n{result.stdout}\n{result.stderr}')
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ('compiler', 'opt', 'plugin', 'llvm_link', 'objdump', 'checker', 'build_dir'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.environ['PATH'] = str(args.compiler.parent) + os.pathsep + os.environ.get('PATH', '')
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source_text = POSITIVE.replace('declare void @consume(ptr)', 'define void @consume(ptr %p) { ret void }')
        source_text = source_text.replace('define ', 'define dllexport ')
        getters = {'get_wide': 'wide', 'get_zeros': 'zeros', 'get_nested': 'nested', 'get_number': 'number', 'get_nan': 'nan'}
        for name, global_name in getters.items():
            source_text += f'\ndefine dllexport ptr @{name}() {{ ret ptr @{global_name} }}\n'
        source_text += '''
define dllexport i32 @recurse(i32 %depth) {
entry:
  %saved = alloca i32, align 16
  store volatile i32 %depth, ptr %saved, align 16
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %base, label %more
base:
  ret i32 13
more:
  %next = sub i32 %depth, 1
  %value = call i32 @recurse(i32 %next)
  %current = load volatile i32, ptr %saved, align 16
  %same = icmp eq i32 %current, %depth
  %sum = add i32 %value, 1
  %checked = select i1 %same, i32 %sum, i32 -10000
  ret i32 %checked
}
'''
        names = ['pointer', 'data', 'floating', 'pure', 'caller', 'recurse', *getters]
        config = directory / 'config.json'
        configuration = {'schema_version': 1, 'functions': {
            name: {'components': {'constant-archive': 'off' if name == 'caller' else 'required'}} for name in names}}
        config.write_text(json.dumps(configuration), encoding='utf-8')
        source, requested, requests = [directory / name for name in ('source.ll', 'requested.ll', 'requests.json')]
        source.write_text(source_text, encoding='utf-8')
        base = [str(args.opt), f'-load-pass-plugin={args.plugin}', '-verify-each']
        run([*base, '-passes=pyobf-native-cff-requests', f'-pyobf-cff-config={config}',
             f'-pyobf-cff-requests-output={requests}', '-S', str(source), '-o', str(requested)])
        pending, plan = directory / 'pending.ll', directory / 'plan.json'
        run([*base, '-passes=pyobf-native-archive-plan', f'-pyobf-cff-config={config}',
             f'-pyobf-archive-plan-output={plan}', '-S', str(requested), '-o', str(pending)])
        package, generated, bindings = [directory / name for name in ('pool.bin', 'pool.cpp', 'bindings.json')]
        run([sys.executable, str(root / 'tools' / 'pack_archive.py'), str(plan), str(package), str(generated), str(bindings)])
        includes = ['-I', str(root / 'include'), '-I', str(root / 'src')]
        runtime = [root / 'src' / 'archive' / name for name in ('format.cpp', 'acquire.cpp', 'require.cpp')]
        runtime += [root / 'backends' / 'windows_user' / 'operations' / name
                    for name in ('memory.cpp', 'crypto.cpp', 'atomic.cpp', 'archive_support.cpp')]
        units = []
        for index, unit in enumerate([*runtime, generated]):
            output = directory / f'unit-{index}.ll'
            run([str(args.compiler), '-std=c++17', '-O0', '-Xclang', '-disable-O0-optnone',
                 '-S', '-emit-llvm', *includes, str(unit), '-o', str(output)])
            units.append(output)
        combined = directory / 'combined.ll'
        run([str(args.llvm_link), '-S', str(pending), *map(str, units), '-o', str(combined)])
        materialized = directory / 'materialized.ll'

        def materialize(manifest=bindings, output=materialized, input_ir=combined, succeeds=True):
            return run([*base, '-passes=pyobf-native-archive-materialize', f'-pyobf-archive-bindings={manifest}',
                        '-S', str(input_ir), '-o', str(output)], succeeds=succeeds)

        materialize()
        protected, report, private_map = [directory / name for name in ('protected.ll', 'coverage.json', 'map.json')]

        def protect(input_ir=materialized, output=protected, configuration_path=config, succeeds=True):
            return run([*base, '-passes=pyobf-native-cff', f'-pyobf-cff-config={configuration_path}',
                        f'-pyobf-cff-requests-input={requests}', f'-pyobf-cff-report={report}',
                        f'-pyobf-cff-private-map={private_map}', '-S', str(input_ir), '-o', str(output)], succeeds=succeeds)

        protect()
        text = protected.read_text()
        if 'pyobf.archive.key-material' in text or '!pyobf.archive.sources' in text or '__pyobf_archive_pending_' in text:
            raise AssertionError('private compiler key/source/pending material survived final CFF')
        coverage = json.loads(report.read_bytes())
        mapping = json.loads(private_map.read_bytes())
        for row in mapping['functions']:
            sites = {site['id']: site for site in row['sites']}
            for source_row in row.get('archive_sources', []):
                if len(source_row['children']) != 9 or any(child['site_id'] not in sites
                        for child in source_row['children']):
                    raise AssertionError('source/acquisition map lacks exact physical child links')
        for row in coverage['functions']:
            if row['selected'] and row['status'] != 'transformed':
                raise AssertionError('archive user/SDK selected function was not protected')
            if 'archive_sources' not in row:
                continue
            sources = row['archive_sources']
            component = next(item for item in row['components'] if item['component'] == 'constant-archive')
            if (sources['requested'] != sources['applied'] or sources['acquisitions'] != sources['complete_acquisitions'] or
                component['applied'] != sources['acquisitions'] * 9):
                raise AssertionError('source coverage was credited without all eight key lanes and the acquisition')
        executable = directory / 'harness.exe'
        run([str(args.compiler), '-std=c++17', str(root / 'tests' / 'archive_protected_smoke.cpp'), '-o', str(executable)])
        plain, secured = directory / 'plain.dll', directory / 'protected.dll'
        run([str(args.compiler), '-shared', str(source), '-o', str(plain)])
        run([str(executable), str(plain)])
        run([str(args.compiler), '-shared', str(protected), '-lbcrypt', '-o', str(secured)])
        run([str(executable), str(secured)])
        run([sys.executable, str(args.checker), str(args.objdump), str(secured), str(report)])

        binary = secured.read_bytes()
        if b'A\0B\xffC!\0' in binary or bytes.fromhex('bc9a78563412f87f') in binary:
            raise AssertionError('selected original constant bytes survived in the protected DLL')
        private = json.loads(bindings.read_bytes())
        if any(bytes.fromhex(row['key_hex']) in binary for row in private['records']):
            raise AssertionError('raw archive key survived in the protected DLL')

        check_failures(args, directory, run, materialize, protect)

        # Re-plan with scalar literals handled by their own component, then exercise
        # split key construction and routed acquisition calls in the real DLL.
        for name, override in configuration['functions'].items():
            override['components'].update({'split-blocks': 'optional', 'common-exit': 'optional',
                'deduplicate-blocks': 'optional', 'internal-calls': 'optional', 'integer-literals': 'optional'})
            if name in ('pure', 'recurse'):
                override['components']['constant-archive'] = 'optional'
                override['components']['integer-literals'] = 'required'
        config.write_text(json.dumps(configuration), encoding='utf-8')
        run([*base, '-passes=pyobf-native-cff-requests', f'-pyobf-cff-config={config}',
             f'-pyobf-cff-requests-output={requests}', '-S', str(source), '-o', str(requested)])
        run([*base, '-passes=pyobf-native-archive-plan', f'-pyobf-cff-config={config}',
             f'-pyobf-archive-plan-output={plan}', '-S', str(requested), '-o', str(pending)])
        run([sys.executable, str(root / 'tools' / 'pack_archive.py'), str(plan), str(package), str(generated), str(bindings)])
        mixed_bindings = json.loads(bindings.read_bytes())
        if len(mixed_bindings['records']) >= len(private['records']):
            raise AssertionError('integer/archive routing did not avoid duplicate scalar collection')
        run([str(args.compiler), '-std=c++17', '-O0', '-Xclang', '-disable-O0-optnone',
             '-S', '-emit-llvm', *includes, str(generated), '-o', str(units[-1])])
        run([str(args.llvm_link), '-S', str(pending), *map(str, units), '-o', str(combined)])
        materialize()
        protect()
        mixed = json.loads(report.read_bytes())
        for name in ('pure', 'recurse'):
            row = next(row for row in mixed['functions'] if row['function'] == name)
            literal = next(item for item in row['components'] if item['component'] == 'integer-literals')
            if row['status'] != 'transformed' or not literal['applied']:
                raise AssertionError('scalar strategy did not cover its original user literals')
        run([str(args.compiler), '-shared', str(protected), '-lbcrypt', '-o', str(secured)])
        run([str(executable), str(secured)])
        run([sys.executable, str(args.checker), str(args.objdump), str(secured), str(report)])

        # Replace legacy slots with state-bound reference tables without changing the
        # materialized pool. The archive verifier must resolve the actual indexed target.
        for override in configuration['functions'].values():
            override['components'].update({'internal-calls': 'off', 'reference-routes': 'optional'})
        config.write_text(json.dumps(configuration), encoding='utf-8')
        protect()
        references = json.loads(report.read_bytes())
        if not any(item['applied'] for row in references['functions'] if row['selected']
                   for item in row['components'] if item['component'] == 'reference-routes'):
            raise AssertionError('real archive acquisitions never exercised indexed reference targets')
        run([str(args.compiler), '-shared', str(protected), '-lbcrypt', '-o', str(secured)])
        run([str(executable), str(secured)])
        run([sys.executable, str(args.checker), str(args.objdump), str(secured), str(report)])

        # Frame only original eligible internal calls. Archive acquisition gates retain
        # their own typed protocol/coverage while reference routing remains enabled.
        for override in configuration['functions'].values():
            override['components']['call-frames'] = 'optional'
        config.write_text(json.dumps(configuration), encoding='utf-8')
        run([*base, '-passes=pyobf-native-cff-requests', f'-pyobf-cff-config={config}',
             f'-pyobf-cff-requests-output={requests}', '-S', str(source), '-o', str(requested)])
        protect()
        frames = json.loads(report.read_bytes())
        if not any(item['applied'] for row in frames['functions'] if row['selected']
                   for item in row['components'] if item['component'] == 'call-frames'):
            raise AssertionError('archive combination never framed an original user call')
        run([str(args.compiler), '-shared', str(protected), '-lbcrypt', '-o', str(secured)])
        run([str(executable), str(secured)])
        run([sys.executable, str(args.checker), str(args.objdump), str(secured), str(report)])

        for override in configuration['functions'].values():
            override['components']['call-preparation'] = 'optional'
        config.write_text(json.dumps(configuration), encoding='utf-8')
        run([*base, '-passes=pyobf-native-cff-requests', f'-pyobf-cff-config={config}',
             f'-pyobf-cff-requests-output={requests}', '-S', str(source), '-o', str(requested)])
        protect()
        prepared = json.loads(report.read_bytes())
        if not any(item['applied'] for row in prepared['functions'] if row['selected']
                   for item in row['components'] if item['component'] == 'call-preparation'):
            raise AssertionError('real archive combination never prepared a framed user call')
        run([str(args.compiler), '-shared', str(protected), '-lbcrypt', '-o', str(secured)])
        run([str(executable), str(secured)])
        run([sys.executable, str(args.checker), str(args.objdump), str(secured), str(report)])

        for override in configuration['functions'].values():
            override['components']['indexed-locals'] = 'optional'
        config.write_text(json.dumps(configuration), encoding='utf-8')
        run([*base, '-passes=pyobf-native-cff-requests', f'-pyobf-cff-config={config}',
             f'-pyobf-cff-requests-output={requests}', '-S', str(source), '-o', str(requested)])
        protect()
        indexed = json.loads(report.read_bytes())
        recurse = next(row for row in indexed['functions'] if row['function'] == 'recurse')
        local = next(item for item in recurse['components'] if item['component'] == 'indexed-locals')
        if local['applied'] != 1 or local['preparation']['objects'] != 1:
            raise AssertionError('archive combination lost its original local or credited generated key/frame/SSA storage')
        run([str(args.compiler), '-shared', str(protected), '-lbcrypt', '-o', str(secured)])
        run([str(executable), str(secured)])
        run([sys.executable, str(args.checker), str(args.objdump), str(secured), str(report)])


if __name__ == '__main__':
    main()
