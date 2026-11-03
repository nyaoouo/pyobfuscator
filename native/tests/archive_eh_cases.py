"""Archive admission and immutable exception-control operand regressions."""
import json
import re


def eh_cases(prepare, directory, header):
    source = header + '''
@eh_type = external constant ptr
@payload = private constant i32 41
declare i32 @__gxx_personality_seh0(...)
declare void @may_throw()
declare i32 @llvm.eh.typeid.for(ptr)
declare void @__cxa_throw(ptr, ptr, ptr)
declare ptr @__cxa_init_primary_exception(ptr, ptr, ptr)
define i32 @f(ptr %object) personality ptr @__gxx_personality_seh0 {
entry:
  %primary = call ptr @__cxa_init_primary_exception(ptr %object, ptr @eh_type, ptr null)
  invoke void @may_throw() to label %normal unwind label %pad
normal:
  %value = load i32, ptr @payload
  ret i32 %value
pad:
  %exception = landingpad { ptr, i32 } catch ptr @eh_type
  %id = call i32 @llvm.eh.typeid.for(ptr @eh_type)
  %selector = extractvalue { ptr, i32 } %exception, 1
  %matches = icmp eq i32 %selector, %id
  br i1 %matches, label %caught, label %resume
caught:
  invoke void @__cxa_throw(ptr %object, ptr @eh_type, ptr null) to label %impossible unwind label %cleanup
impossible:
  unreachable
cleanup:
  %escaping = landingpad { ptr, i32 } cleanup
  resume { ptr, i32 } %escaping
resume:
  resume { ptr, i32 } %exception
}
'''
    config = directory / "hybrid-archive.json"
    config.write_text(json.dumps({"schema_version": 1, "functions": {"f": {
        "coverage": "hybrid-eh", "components": {"constant-archive": "required"}}}}))
    extra = [f"-pyobf-cff-config={config}"]
    result = prepare(source, "f", succeeds=False)
    if "branches, switches, and returns only" not in result.stderr:
        raise AssertionError("default whole archive stopped rejecting EH")
    plan, output = prepare(source, "f", extra=extra)
    if len(plan["records"]) != 1 or plan["records"][0]["data_hex"] != "29000000":
        raise AssertionError("exception ABI data entered the ordinary typed archive")
    for unchanged in ("@eh_type = external constant ptr", "catch ptr @eh_type",
            "@__cxa_throw(ptr %object, ptr @eh_type, ptr null)",
            "@__cxa_init_primary_exception(ptr %object, ptr @eh_type, ptr null)"):
        if unchanged not in output:
            raise AssertionError("archive changed an exception control operand: " + unchanged)
    if not re.search(r"@llvm\.eh\.typeid\.for(?:\.p0)?\(ptr @eh_type\)", output):
        raise AssertionError("archive changed the actual exception type-ID argument")
    shared = source.replace("@eh_type = external constant ptr", "@eh_type = private constant i64 17").replace(
        "%value = load i32, ptr @payload", "%shared = load i64, ptr @eh_type\n  %value = load i32, ptr @payload")
    for text, expected in ((shared, "exception ABI/control use"),
            (source.replace("x86_64-w64-windows-gnu", "x86_64-pc-windows-msvc"), "target model is not verified"),
            (source.replace("__gxx_personality_seh0", "foreign_personality"), "GNU C++ landingpad personality")):
        result = prepare(text, "f", succeeds=False, extra=extra)
        if expected not in result.stderr:
            raise AssertionError("hybrid archive refusal occurred outside its boundary: " + result.stderr)
