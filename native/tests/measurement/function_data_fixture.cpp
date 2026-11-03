extern "C" {
__declspec(dllexport) unsigned measurement_data = 7;
volatile unsigned extent_data_bss_prefix;
volatile unsigned extent_data_bss;
volatile unsigned extent_data_rw_prefix = 11;
volatile unsigned extent_data_rw = 19;
extern volatile const unsigned extent_data_ro[4] = {3, 5, 11, 23};

__declspec(dllexport) unsigned extent_data_target(unsigned value) {
    extent_data_bss = value;
    return extent_data_bss + extent_data_rw + extent_data_ro[value & 3];
}
__declspec(dllexport) unsigned measurement_target(unsigned value) { return extent_data_target(value); }
}
