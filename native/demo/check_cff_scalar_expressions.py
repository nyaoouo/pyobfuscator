"""Execute production APInt/mask/codec emitters across all admitted scalar widths."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path

from check_cff_expressions import run


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "generator", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, vectors = directory / "expressions.ll", directory / "vectors.json"
        run([str(args.generator), str(source), str(vectors)])
        run([str(args.opt), "-passes=verify", "-disable-output", str(source)])
        records = json.loads(vectors.read_text())
        declarations = "\n".join(
            f'extern "C" void {label}_{width}(std::uint32_t, std::uint64_t*);'
            for width in range(1, 129) for label in ("mask_lit", "mask_cmp", "mask_arc", "mask_ref", "mask_prep", "mask_local", "mask_import"))
        declarations += "\n" + "\n".join(
            f'extern "C" void encode_{width}(std::uint32_t,std::uint64_t,std::uint64_t,std::uint64_t*);'
            for width in range(2, 129))
        values = []
        for row in records:
            pairs = ",".join("{" + ",".join(f"0x{item}ull" for item in row[name]) + "}"
                             for name in ("input", "literal", "key", "encoded", "archive", "reference", "preparation", "locals", "imports"))
            values.append(f"{{{row['width']},{row['state']}u,{pairs}}}")
        pointers = ",\n".join(f"{{mask_lit_{width},mask_cmp_{width},mask_arc_{width},mask_ref_{width},mask_prep_{width},mask_local_{width},mask_import_{width},"
                               f"{'nullptr' if width == 1 else f'encode_{width}'}}}"
                               for width in range(1, 129))
        harness = directory / "harness.cpp"
        harness.write_text(
            "#include <cstdint>\n#include <set>\n#include <utility>\n" + declarations +
            "\nusing Mask=void(*)(std::uint32_t,std::uint64_t*);\n"
            "using Encode=void(*)(std::uint32_t,std::uint64_t,std::uint64_t,std::uint64_t*);\n"
            "struct Functions{Mask literal,key,archive,reference,preparation,locals,imports;Encode encode;};\nconst Functions functions[]={\n" + pointers +
            "\n};\nstruct Row{unsigned width;std::uint32_t state;std::uint64_t input[2],literal[2],key[2],encoded[2],archive[2],reference[2],preparation[2],locals[2],imports[2];};\n"
            "const Row rows[]={\n" + ",\n".join(values) + "\n};\n" + r'''
int main(){
    std::set<std::pair<std::uint64_t,std::uint64_t>> outputs[8];
    for(const auto &row:rows){
        std::uint64_t actual[2]={};
        const auto &fn=functions[row.width-1];
        fn.literal(row.state,actual);
        if(actual[0]!=row.literal[0] || actual[1]!=row.literal[1])return 1;
        fn.key(row.state,actual);
        if(actual[0]!=row.key[0] || actual[1]!=row.key[1])return 2;
        fn.archive(row.state,actual);
        if(actual[0]!=row.archive[0] || actual[1]!=row.archive[1])return 5;
        fn.reference(row.state,actual);
        if(actual[0]!=row.reference[0] || actual[1]!=row.reference[1])return 6;
        fn.preparation(row.state,actual);
        if(actual[0]!=row.preparation[0] || actual[1]!=row.preparation[1])return 7;
        fn.locals(row.state,actual);
        if(actual[0]!=row.locals[0] || actual[1]!=row.locals[1])return 8;
        fn.imports(row.state,actual);
        if(actual[0]!=row.imports[0] || actual[1]!=row.imports[1])return 9;
        if(!fn.encode)continue;
        fn.encode(row.state,row.input[0],row.input[1],actual);
        if(actual[0]!=row.encoded[0] || actual[1]!=row.encoded[1])return 3;
        if(row.width<=8 && !outputs[row.width-1].insert({actual[0],actual[1]}).second)return 4;
    }
    return 0;
}
''', encoding="utf-8")
        for optimization in ("-O0", "-O2"):
            binary = directory / f"expressions{optimization}.exe"
            run([str(args.compiler), optimization, str(source), str(harness), "-o", str(binary)])
            run([str(binary)])
        ir = source.read_text()
        body = re.search(r"define void @mask_lit_64\(.*?\n\}", ir, re.S)
        if body is None or "-2048144789" not in body.group():
            raise AssertionError("production mask multiplier is missing")
        changed = body.group().replace("-2048144789", "-2048144787")
        broken = directory / "broken.ll"
        broken.write_text(ir[:body.start()] + changed + ir[body.end():], encoding="utf-8")
        binary = directory / "broken.exe"
        run([str(args.compiler), str(broken), str(harness), "-o", str(binary)])
        run([str(binary)], succeeds=False)


if __name__ == "__main__":
    main()
