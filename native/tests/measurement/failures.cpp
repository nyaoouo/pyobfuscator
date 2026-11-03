#include "failure_fixture.hpp"

#include <cstdio>
#include <cstring>

using namespace pyobfuscator::native::measurement;
using namespace capture_test;

namespace {
void rejected(Status expected) {
    auto result = capture(input(), nullptr);
    require(result.data().status == expected && cleared(result.data()), "wrong failure source or surviving partial data");
    require(counters.views == 0 && counters.allocations == counters.releases, "failure retained resources");
}
}

int main(int argc, char **argv) {
    reset_fixture();
    if (argc == 2 && std::strcmp(argv[1], "close-failure") == 0) {
        auto result = capture(input(), nullptr);
        require(result.data().status == Status::ok, "close failure setup");
        closing_data = &result.data(); faults.close = true; result.reset();
        return 2;
    }
    { auto descriptor = input(); descriptor.owner = 0;
      auto result = capture(descriptor, nullptr);
      require(result.data().status == Status::invalid_descriptor && counters.opens == 0, "preflight did not reject before acquisition"); }
    for (unsigned scenario = 0; scenario != 9; ++scenario) {
        reset_fixture();
        auto descriptor = input();
        Range ranges[2]{{0x1000, 32}, {0x1010, 16}};
        std::uint32_t fixups[2]{0x1000, 0x1000};
        switch (scenario) {
        case 0: descriptor.kind = 4; break;
        case 1: descriptor.range_count = 0; break;
        case 2: descriptor.ranges = nullptr; break;
        case 3: ranges[0] = {0x2fff, 2}; descriptor.ranges = ranges; break;
        case 4: descriptor.ranges = ranges; descriptor.range_count = 2; break;
        case 5: descriptor.fixup_count = 1; break;
        case 6: fixups[0] = 0x101c; descriptor.fixups = fixups; descriptor.fixup_count = 1; break;
        case 7: descriptor.fixups = fixups; descriptor.fixup_count = 2; break;
        case 8: descriptor.preferred_base = UINT64_MAX; break;
        }
        auto result = capture(descriptor, nullptr);
        require(result.data().status == (scenario == 0 ? Status::unsupported : Status::invalid_descriptor) &&
            cleared(result.data()) && counters.opens == 0 && counters.allocations == 0,
            "malformed span/fixup descriptor reached backend acquisition or retained data");
    }
    reset_fixture(); faults.open = true; rejected(Status::unavailable);
    reset_fixture(); faults.partial_view = true; rejected(Status::unavailable);
    reset_fixture(); faults.allocation = true; rejected(Status::allocation_failed);
    reset_fixture(); faults.read = true; rejected(Status::read_failed);
    require(counters.hashes == 0, "failed read reached hashing");
    reset_fixture(); faults.hash = true; rejected(Status::crypto_failed);
    reset_fixture(); faults.clock_failure = 1; rejected(Status::clock_failed);
    require(counters.reads == 0 && counters.hashes == 0, "failed start clock reached the subject");
    reset_fixture(); faults.clock_failure = 2; rejected(Status::clock_failed);
    reset_fixture(); faults.backward = true; rejected(Status::clock_failed);
    reset_fixture(); faults.frequency = true; rejected(Status::clock_failed);
    reset_fixture(); faults.reenter = true;
    {
        auto result = capture(input(), nullptr);
        require(result.data().status == Status::ok && result.data().read_started == 100 &&
            result.data().read_completed == 400 && counters.reads == 2 && counters.views == 1,
            "reentrant capture shared data, timing or lifetime");
        closing_data = &result.data(); result.reset(); closing_data = nullptr;
        require(result.data().status == Status::unavailable && cleared(result.data()), "reset retained a successful snapshot");
    }
    reset_fixture();
    std::puts("native capture failure origins, dirty hash output, material/data erasure, reentry and cleanup pass");
}
