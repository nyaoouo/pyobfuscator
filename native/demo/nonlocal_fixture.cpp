#include <csetjmp>
#include <cstdio>

static std::jmp_buf checkpoint;

extern "C" __attribute__((noinline)) int resume_case(int input) {
    switch (setjmp(checkpoint)) {
    case 0: break;
    case 7: return 107;
    default: return -2;
    }
    volatile int value = input;
    if (input > 0) {
        value = value + 3;
        std::longjmp(checkpoint, 7);
    }
    return value + 1;
}

int main() {
    if (resume_case(0) != 1 || resume_case(1) != 107) return 1;
    std::puts("NONLOCAL_OK");
    return 0;
}
