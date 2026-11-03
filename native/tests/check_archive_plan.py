"""Verify real archive planning, raw storage, closed uses and unfinished-output rejection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from archive_plan_cases import FUNCTIONS, GLOBAL_BYTES, HEADER, LAYOUT, NEGATIVE, POSITIVE
from archive_eh_cases import eh_cases


def run(command: list[str], *, succeeds: bool = True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f'archive plan command differs: {command}\n{result.stdout}\n{result.stderr}')
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ('opt', 'plugin', 'build_dir'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.environ['PATH'] = str(args.opt.parent) + os.pathsep + os.environ.get('PATH', '')
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, planned, plan = [directory / name for name in ('source.ll', 'planned.ll', 'plan.json')]
        base = [str(args.opt), f'-load-pass-plugin={args.plugin}', '-verify-each', '-pyobf-cff-markers=false']

        def prepare(text: str, functions: str, *, succeeds: bool = True, extra: list[str] = ()):
            source.write_text(text, encoding='utf-8')
            plan.unlink(missing_ok=True)
            run([str(args.opt), '-passes=verify', '-disable-output', str(source)])
            result = run([*base, '-passes=pyobf-native-archive-plan', f'-pyobf-cff-functions={functions}',
                          f'-pyobf-archive-plan-output={plan}', *extra, '-S', str(source), '-o', str(planned)],
                         succeeds=succeeds)
            if not succeeds:
                if plan.exists():
                    raise AssertionError('unsupported source produced a usable private plan')
                return result
            return json.loads(plan.read_bytes()), planned.read_text()

        document, ir = prepare(POSITIVE, FUNCTIONS)
        rows = document['records']
        if [row['data_hex'].lower() for row in rows[:7]] != GLOBAL_BYTES:
            raise AssertionError('global storage bits/order/padding differ from the source')
        if [row['kind'] for row in rows[:7]] != ['code_units8', 'bytes', 'code_units16', 'integer',
                                                'binary64', 'code_units32', 'bytes']:
            raise AssertionError('global type classification differs')
        if rows[0]['alignment'] != 64 or rows[3]['alignment'] != 16:
            raise AssertionError('declared global alignment was not retained')
        if not re.search(r'@secret = private global \[7 x i8\] zeroinitializer, align 64', ir):
            raise AssertionError('archive replaced the original global identity/type/alignment')
        if '@live = internal global i32 9' not in ir:
            raise AssertionError('archive changed mutable program state')
        if '0x7FF8123456789ABC' in ir or '0x7FF8000000000011' in ir or '!invariant.load' in ir:
            raise AssertionError('source FP bits or invalidated invariant load remain in intermediate code')
        if any(flag in ir for flag in ('memory(none)', 'nofree', 'nosync', 'speculatable', 'willreturn')):
            raise AssertionError('inferred purity survived runtime writes/crypto/synchronization')
        if len(re.findall(r'^[-\w]+:', ir, re.M)) != len(re.findall(r'^[-\w]+:', POSITIVE, re.M)):
            raise AssertionError('planning changed CFG edges while preparing PHI operands')
        def branches(text):
            return [' '.join(line.split(', !', 1)[0].split()) for line in text.splitlines()
                    if line.strip().startswith('br ')]
        if branches(ir) != branches(POSITIVE):
            raise AssertionError(f'branch snapshot differs: original={branches(POSITIVE)!r} planned={branches(ir)!r}')
        if not re.search(r'phi double \[ %pyobf.archive.value', ir):
            raise AssertionError('PHI immediate was not materialized on its incoming edge')
        floating = re.search(r'define double @floating[^}]+}', ir, re.S).group()
        for block, following in (('yes', 'no'), ('no', 'merge')):
            segment = re.search(rf'{block}:.*?{following}:', floating, re.S).group()
            if 'call void @__pyobf_archive_pending_' not in segment or 'load double' not in segment:
                raise AssertionError('a PHI value bypassed its own predecessor preparation')
        gate_count = len(re.findall(r'call void @__pyobf_archive_pending_', ir))
        slots = len(re.findall(r'store volatile i32 0,.*!pyobf.archive.key-slot', ir))
        clear = len(re.findall(r'store volatile i32 0,.*!pyobf.archive.key-clear', ir))
        if gate_count <= len(rows) or slots != gate_count * 8 or clear != slots:
            raise AssertionError(f'shared globals/key frames differ: records={len(rows)} gates={gate_count} '
                                 f'key_slots={slots} key_clears={clear}')
        digest = hashlib.sha256(plan.read_bytes()).hexdigest()
        if digest.upper() not in ir:
            raise AssertionError('private-plan hash does not bind exact output bytes')
        private_copy = plan.read_bytes()
        for passes in ('pyobf-native-cff', 'pyobf-native-cff-requests', 'pyobf-native-archive-plan'):
            result = run([*base, f'-passes={passes}', f'-pyobf-cff-functions={FUNCTIONS}',
                          f'-pyobf-archive-plan-output={directory / "reentry.json"}',
                          '-disable-output', str(planned)], succeeds=False)
            if 'pending wrapper and state-key' not in result.stderr:
                raise AssertionError(f'unfinished boundary missed in {passes}: {result.stderr}')
        if (directory / 'reentry.json').exists():
            raise AssertionError('repeated planning overwrote a pending plan')
        if plan.read_bytes() != private_copy:
            raise AssertionError('a rejected re-entry changed the private plan')

        # Hand the actual compiler output to the existing production packer.
        outputs = [directory / name for name in ('pool.bin', 'pool.cpp', 'bindings.json')]
        run([sys.executable, str(root / 'tools' / 'pack_archive.py'), str(plan), *map(str, outputs)])
        bindings = json.loads(outputs[2].read_bytes())
        if bindings['plan_sha256'] != digest or len(bindings['records']) != len(rows):
            raise AssertionError('compiler/packer handoff lost manifest identity or records')

        # The same integer's low store bytes precede allocation padding on big endian.
        big = HEADER.replace(LAYOUT, 'E-p:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128')
        big += '@s = private constant i33 8589934591, align 8\ndefine ptr @f() { ret ptr @s }'
        big_rows, _ = prepare(big, 'f')
        if big_rows['records'][0]['data_hex'].lower() != '01ffffffff000000':
            raise AssertionError('big-endian store representation was shifted into allocation padding')

        types = [
            ('i1', '1', '01', 'integer'),
            ('i128', '340282366920938463463374607431768211455', 'ff' * 16, 'integer'),
            ('half', '0xH8000', '0080', 'binary16'),
            ('bfloat', '0xR7FC1', 'c17f', 'bfloat16'),
            ('float', '0x7FF8000020000000', '0100c07f', 'binary32'),
            ('double', '0x8000000000000000', '0000000000000080', 'binary64'),
            ('x86_fp80', '0xK7FFFC000000000000001', '01000000000000c0ff7f' + '00' * 6, 'x87_80'),
            ('fp128', '0xL00000000000000007FFF800000000000', '0000000000000000000000000080ff7f', 'binary128'),
            ('[2 x float]', '[float 0.0, float 0x8000000000000000]', '0000000000000080', 'bytes'),
        ]
        for type_name, value, bits, kind in types:
            source_text = HEADER + f'@s = private constant {type_name} {value}\ndefine ptr @f() {{ ret ptr @s }}'
            matrix, _ = prepare(source_text, 'f')
            record = matrix['records'][0]
            if len(matrix['records']) != 1 or record['data_hex'].lower() != bits or record['kind'] != kind:
                raise AssertionError(f'bit-exact typed planning differs for {type_name}: {record}')
            # Every admitted compiler representation must also satisfy the production schema.
            run([sys.executable, str(root / 'tools' / 'pack_archive.py'), str(plan), *map(str, outputs)])

        narrow = HEADER.replace(LAYOUT, 'e-p:32:32-i64:64-i128:128-f80:128-n8:16:32-S128').replace(
            'x86_64-w64-windows-gnu', 'i686-w64-windows-gnu')
        narrow += '@s = private constant [2 x i8] c"X\\00"\ndefine ptr @f() { ret ptr @s }'
        _, narrow_ir = prepare(narrow, 'f')
        if not re.search(r'declare void @__pyobf_archive_pending_[^(]+\(ptr, ptr, i32\)', narrow_ir):
            raise AssertionError('archive gate used build-host size_t instead of target pointer width')

        intrinsic = HEADER + '''declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)
            define void @f(ptr %dest) {
              call void @llvm.memset.p0.i64(ptr %dest, i8 7, i64 4, i1 false)
              ret void
            }'''
        intrinsic_rows, _ = prepare(intrinsic, 'f')
        if [row['bit_width'] for row in intrinsic_rows['records']] != [8, 64]:
            raise AssertionError('fixed intrinsic immediate was rewritten as runtime data')

        reflective = HEADER + '''declare i1 @llvm.is.constant.i32(i32)
            define i32 @f() {
              %constant = call i1 @llvm.is.constant.i32(i32 7)
              call void asm sideeffect "", "i"(i32 9)
              ret i32 42
            }'''
        reflective_rows, reflective_ir = prepare(reflective, 'f')
        if len(reflective_rows['records']) != 1 or reflective_rows['records'][0]['data_hex'] != '2A000000':
            raise AssertionError('constant-reflection or assembly-control operands were treated as data')
        if '@llvm.is.constant.i32(i32 7)' not in reflective_ir or '"i"(i32 9)' not in reflective_ir:
            raise AssertionError('planning changed intrinsic constantness or an assembly constraint')

        marker = HEADER + '''declare void @pyobf_native_contribution_site_v1(ptr, i32) nounwind
            define i32 @f(ptr %lease, i32 %value) {
              call void @pyobf_native_contribution_site_v1(ptr %lease, i32 101)
              %sum = add i32 %value, 7
              ret i32 %sum
            }'''
        marker_rows, marker_ir = prepare(marker, 'f')
        if ([row['data_hex'] for row in marker_rows['records']] != ['07000000'] or
                'call void @pyobf_native_contribution_site_v1(ptr %lease, i32 101)' not in marker_ir):
            raise AssertionError('archive treated a closed source descriptor as runtime data')

        eh_cases(prepare, directory, HEADER)
        for text, message in NEGATIVE:
            result = prepare(text, 'f', succeeds=False)
            if message not in result.stderr:
                raise AssertionError(f'unsupported source missed {message!r}: {result.stderr}')
        for text, functions, message, extra in (
            (POSITIVE.replace(f'target datalayout = "{LAYOUT}"\n', '').replace(
                'target triple = "x86_64-w64-windows-gnu"\n', ''), FUNCTIONS, 'explicit 32-bit or 64-bit', []),
            (POSITIVE, 'absent', 'missing', []),
            (HEADER + 'declare i32 @f()', 'f', 'declaration', []),
            (HEADER + 'define i32 @f() { ret i32 7 }', 'f', 'whole-function', ['-pyobf-cff-region=f:entry:exit']),
        ):
            result = prepare(text, functions, succeeds=False, extra=extra)
            if message not in result.stderr:
                raise AssertionError(f'archive preflight missed {message!r}: {result.stderr}')


if __name__ == '__main__':
    main()
