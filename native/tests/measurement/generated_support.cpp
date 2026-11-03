extern "C" {
extern __declspec(dllexport) const unsigned char measurement_data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
__declspec(dllexport) unsigned external_target(unsigned value) { return value + 17u; }
__declspec(dllexport) unsigned measurement_target(unsigned value) { return value; }
}
