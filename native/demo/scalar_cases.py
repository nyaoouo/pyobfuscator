"""Typed-data differential fixtures; IR construction is separate from test orchestration."""

from __future__ import annotations


WIDTHS = (1, 2, 7, 8, 16, 31, 32, 33, 63, 64, 65, 127, 128)
PATTERN = 0xc159ade72b8046f3d68e9137a45bc20d


def literal(width: int) -> int:
    return PATTERN & ((1 << width) - 1)


def input_ir(width: int) -> str:
    text = '''  %low128 = zext i64 %low to i128
  %high128 = zext i64 %high to i128
  %top = shl i128 %high128, 64
  %joined = or i128 %low128, %top
'''
    return text + (f"  %x = trunc i128 %joined to i{width}\n" if width < 128 else "")


def source_ir() -> str:
    functions = []
    for width in WIDTHS:
        value = "%joined" if width == 128 else "%x"
        constant = literal(width)
        other = (PATTERN >> 31) & ((1 << width) - 1)
        shift = width // 4
        functions.append(f'''@sink_{width} = internal global i{width} 0
define i64 @literal_{width}(i64 %low, i64 %high) {{
entry:
{input_ir(width)}  %a = add i{width} {value}, {constant}
  %b = xor i{width} %a, {other}
  %left = shl i{width} %b, {shift}
  %right = ashr i{width} %b, {shift}
  %signed = icmp slt i{width} {value}, {constant}
  %unsigned = icmp ult i{width} {value}, {other}
  %pick = xor i1 %signed, %unsigned
  %selected = select i1 %pick, i{width} %left, i{width} %right
  store volatile i{width} %selected, ptr @sink_{width}
  %seen = load volatile i{width}, ptr @sink_{width}
''' + (f"  %wide = zext i{width} %seen to i128\n" if width < 128 else "") + f'''  %lo = trunc i128 {'%wide' if width < 128 else '%seen'} to i64
  %top_result = lshr i128 {'%wide' if width < 128 else '%seen'}, 64
  %hi = trunc i128 %top_result to i64
  %result = xor i64 %lo, %hi
  ret i64 %result
}}
''')
        if width < 2: continue
        for predicate, side in (("eq", 1), ("ne", 0)):
            operands = f"{value}, {constant}" if side else f"{constant}, {value}"
            functions.append(f'''define i32 @{predicate}_{width}(i64 %low, i64 %high) {{
entry:
{input_ir(width)}  %check = icmp {predicate} i{width} {operands}
  br i1 %check, label %yes, label %no
yes:
  ret i32 111
no:
  ret i32 222
}}
''')
    functions.append(r'''
define i64 @literal_loop(i64 %x) {
entry:
  br label %loop
loop:
  %i = phi i64 [0, %entry], [%next, %loop]
  %accum = phi i64 [%x, %entry], [%new, %loop]
  %quotient = udiv i64 %accum, 3
  %remainder = srem i64 %accum, 7
  %shift = and i64 %i, 63
  %part = shl i64 %quotient, %shift
  %new = xor i64 %part, %remainder
  %next = add i64 %i, 1
  %again = icmp ult i64 %next, 4
  br i1 %again, label %loop, label %done
done:
  ret i64 %new
}
define i32 @same_sign(i32 %x) {
entry:
  %check = icmp samesign eq i32 %x, 1073741823
  %result = zext i1 %check to i32
  ret i32 %result
}
define i32 @mixed(i64 %x, ptr %p) {
entry:
  %a = icmp eq i64 %x, 15484915602873238029
  %b = icmp eq ptr %p, null
  %pick = xor i1 %a, %b
  %result = zext i1 %pick to i32
  ret i32 %result
}
define i1 @only_order(i64 %x) {
entry:
  %result = icmp slt i64 %x, 123
  ret i1 %result
}
define i1 @boolean_eq(i1 %x) {
entry:
  %result = icmp eq i1 %x, true
  ret i1 %result
}
define i1 @pointer_eq(ptr %x) {
entry:
  %result = icmp eq ptr %x, null
  ret i1 %result
}
define i1 @vector_eq(<2 x i32> %x) {
entry:
  %pair = icmp eq <2 x i32> %x, <i32 19, i32 37>
  %result = extractelement <2 x i1> %pair, i32 0
  ret i1 %result
}
define i1 @oversized_eq(i256 %x) {
entry:
  %result = icmp eq i256 %x, 123
  ret i1 %result
}
define i256 @oversized_literal(i256 %x) {
entry:
  %result = xor i256 %x, 123
  ret i256 %result
}
define i32 @comparison_folded(i32 %x) {
entry:
  %zero = and i32 %x, 0
  %check = icmp eq i32 %zero, 123
  %result = zext i1 %check to i32
  ret i32 %result
}
''')
    return "\n".join(functions)


def harness_source() -> str:
    declarations, descriptors = [], []
    for width in WIDTHS:
        declarations.append(f'extern "C" std::uint64_t literal_{width}(std::uint64_t,std::uint64_t);')
        eq, ne = "nullptr", "nullptr"
        if width >= 2:
            for prefix in ("eq", "ne"):
                declarations.append(f'extern "C" unsigned {prefix}_{width}(std::uint64_t,std::uint64_t);')
            eq, ne = f"eq_{width}", f"ne_{width}"
        value = literal(width)
        descriptors.append(f"{{literal_{width},{eq},{ne},0x{value & ((1 << 64) - 1):x}ull,0x{value >> 64:x}ull}}")
    return "#include <cstdint>\n#include <cstdio>\n" + "\n".join(declarations) + r'''
extern "C" std::uint64_t literal_loop(std::uint64_t);
extern "C" unsigned same_sign(unsigned);
extern "C" unsigned mixed(std::uint64_t,void*);
struct Case{
    std::uint64_t(*literal)(std::uint64_t,std::uint64_t);
    unsigned(*eq)(std::uint64_t,std::uint64_t);
    unsigned(*ne)(std::uint64_t,std::uint64_t);
    std::uint64_t low,high;
};
const Case cases[]={
''' + ",\n".join(descriptors) + r'''
};
int main(){
    std::uint64_t checksum=0;
    for(const auto &row:cases){
        if(row.eq && (row.eq(row.low,row.high)!=111 || row.ne(row.low,row.high)!=222))return 1;
        for(std::uint64_t n=0;n<1000;++n){
            const std::uint64_t lo=n*0x13579bdfcafebabeull;
            const std::uint64_t hi=~(n*0x9e3779b1ull);
            checksum=checksum*131+row.literal(lo,hi);
            if(row.eq)checksum=checksum*131+row.eq(lo,hi)+row.ne(lo,hi);
        }
        checksum^=row.literal(row.low,row.high);
        checksum^=row.literal(~row.low,~row.high);
    }
    for(std::uint64_t n=0;n<1000;++n)checksum=checksum*131+literal_loop(n*0xf0123456789abcdfull);
    if(same_sign(1073741823)!=1 || same_sign(0)!=0)return 2;
    int local=0;
    if(mixed(15484915602873238029ull,nullptr)!=0 || mixed(15484915602873238029ull,&local)!=1)return 3;
    std::printf("%llu\n",static_cast<unsigned long long>(checksum));
    return 0;
}
'''
