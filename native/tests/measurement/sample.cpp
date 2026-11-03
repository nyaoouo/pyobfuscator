#ifndef OFFSET
#define OFFSET 1
#endif
extern "C" __declspec(dllexport) int measurement_target(int input) {
    volatile int value = input;
    return value * 3 + OFFSET;
}
extern "C" __declspec(dllexport) const unsigned char measurement_data[8] = {1, 2, 3, 4, 5, 6, 7, 8};

// An actual loader-adjusted DIR64 inside the measured executable section.
#ifdef _MSC_VER
#pragma section(".capture", execute, read)
#define CAPTURE_TEXT __declspec(allocate(".capture"))
#else
#define CAPTURE_TEXT __attribute__((section(".text"), used))
#endif
extern "C" __declspec(dllexport) CAPTURE_TEXT int (*const measurement_relocation)(int) = &measurement_target;
