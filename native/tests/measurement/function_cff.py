"""Read complete actual CFF bodies; refuse pre-instrumentation object references."""
from check_capture import check_native
from coff_layout import parse_object
from function_subject import function_subject
from pe_layout import parse_image
from cff_build import run


def check_functions(args, directory, native, binary, combined, default_object):
    original = native.read_bytes(); data = binary.read_bytes(); image = parse_image(data)
    obj = parse_object(original)
    baseline = directory / "before-cff.obj"
    run([args.compiler, "-O2", "-fno-lto", "-ffunction-sections", "-c", combined, "-o", baseline])
    for index, pattern in enumerate(("7Capture4dataEv", "11measurement6detail8validate")):
        names = [symbol.name for symbol in obj.symbols if symbol.type == 0x20 and symbol.section > 0 and pattern in symbol.name]
        if len(names) != 1: raise AssertionError("authored CFF capture getter/validator inventory differs")
        subject = function_subject(original, data, image, 0x401 + index, names[0])
        check_native(binary, args.runtime_directory, directory, binary, data, image, subject)
        try: function_subject(default_object.read_bytes(), data, image, subject.tag, names[0])
        except ValueError as error:
            if not any(reason in str(error) for reason in ("offset-zero root definition", "mixed function ownership")):
                raise
        else: raise AssertionError("shared-section production object supplied closed function ownership")
        try: function_subject(baseline.read_bytes(), data, image, subject.tag, names[0])
        except ValueError as error:
            if "bytes disagree" not in str(error): raise
        else: raise AssertionError("pre-instrumentation reference admitted after actual CFF code mutation")
    print("two actual complete CFF getter/validator subjects match native reads; pre-CFF references refuse")
