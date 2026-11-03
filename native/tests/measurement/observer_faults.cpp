#include "observer_fixture.hpp"

#include <cstdio>
#include <cstring>

namespace {
std::vector<std::uint8_t> read(const char *path) {
    auto *file = std::fopen(path, "rb"); observer_test::require(file != nullptr, "fault input open");
    std::vector<std::uint8_t> data;
    for (int value; (value = std::fgetc(file)) != EOF;) {
        observer_test::require(data.size() < 512 * 1024, "fault input budget"); data.push_back(static_cast<std::uint8_t>(value));
    }
    observer_test::require(!std::ferror(file) && std::fclose(file) == 0, "fault input read"); return data;
}
}
int main(int argc, char **argv) {
    using namespace observer_test;
    require(argc == 4 || argc == 5, "fault metadata/package/plaintext and optional terminal failure");
    const auto meta = read(argv[1]); package = read(argv[2]); plaintext = read(argv[3]);
    require(meta.size() == 84, "typed fault metadata");
    std::memcpy(&identity, meta.data(), 52); std::memcpy(words, meta.data() + 52, 32);
    if (argc == 5) {
        reset();
        auto made = make(); auto lease = made.owner.lease(); auto result = observer::observe(lease);
        if (std::strcmp(argv[4], "module-close") == 0) capture_test::faults.close = true;
        else if (std::strcmp(argv[4], "provider-close") == 0) fail_release = true;
        else return 2;
        return 3;
    }
    policies(); races(); failures();
    std::puts("controlled clocks/cache poison/old snapshots, independent reads/reentry/late ordering/close, OOM/erasure/pins and failure provenance pass");
}
