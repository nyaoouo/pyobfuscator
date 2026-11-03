#include <windows.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        return 2;
    }
    HMODULE module = LoadLibraryA(argv[1]);
    if (module == nullptr) {
        return 3;
    }
    auto *probe = reinterpret_cast<int (*)()>(
        GetProcAddress(module, "pyobf_native_sample_probe"));
    const int result = probe == nullptr ? -1 : probe();
    FreeLibrary(module);
    return result == 7 ? 0 : 4;
}
