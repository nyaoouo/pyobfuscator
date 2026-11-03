#include "runtime_fixture.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int pyobf_native_demo_run(int, int, void (*)(std::uint32_t, void *), void *);

int main(int argc, char **argv) {
    using namespace decoy_fixture;
    require(argc == 5, "real/decoy images, mode and status supplied");
    initialize_images(argv[1], argv[2]);
    if (std::strcmp(argv[3], "suite") == 0) suite();
    else {
        reset();
        const bool denied = std::strncmp(argv[3], "decoy", 5) == 0;
        counters.denied = denied || std::strcmp(argv[3], "forged-denied") == 0;
        counters.public_allocation = denied ? 0 : 3;
        if (std::strcmp(argv[3], "failed-hash") == 0) counters.real_hash_succeeds = false;
        if (std::strcmp(argv[3], "decoy-failed-hash") == 0) counters.decoy_hash_succeeds = false;
        const bool invalid_plaintext = std::strcmp(argv[3], "corrupt-real") == 0 || std::strcmp(argv[3], "decoy-corrupt") == 0;
        const int corrupt = std::strcmp(argv[3], "corrupt-real") == 0 ? 1 : std::strcmp(argv[3], "decoy-corrupt") == 0 ? 2 : 0;
        require(pyobf_native_demo_run(5, corrupt, observe, nullptr) == std::atoi(argv[4]), "post-emission fault result");
        require(counters.real_load_attempts == 0 && counters.real_entries == 0, "post-emission fault cannot load or enter real image");
        require(counters.invalid_load_attempts == unsigned(invalid_plaintext), "patched auth status cannot manufacture valid plaintext");
        require(counters.decoy_entries == unsigned(std::atoi(argv[4]) == 101), "one decoy entry or bounded refusal");
        verify_clean();
        std::puts("post-emission real/decoy release fault reached observed bounded outcome");
    }
}
