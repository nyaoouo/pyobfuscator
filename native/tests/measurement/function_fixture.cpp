static __attribute__((noinline)) unsigned private_leaf(unsigned value) { return (value * 3u) ^ 17u; }
extern "C" __declspec(dllexport) unsigned extent_leaf(unsigned value) { return (value * 5u) ^ 23u; }
extern "C" __declspec(dllexport) __attribute__((noinline)) int extent_throw(int value) {
    if (value < 0) throw value;
    return value + 3;
}
extern "C" __declspec(dllexport) unsigned extent_eh(int value) {
    try { return private_leaf(extent_throw(value)); }
    catch (int token) { return private_leaf(unsigned(token) + 71u); }
}
extern "C" int extent_split(int);
extern "C" __declspec(dllexport) int measurement_target(int value) { return extent_split(value); }
extern "C" __declspec(dllexport) const unsigned char measurement_data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
