#include "measurement/observer_internal.hpp"

#include <cstdio>
#include <cstdlib>

namespace observer = pyobfuscator::native::measurement::observer;
namespace detail = observer::detail;

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    auto *file = std::fopen(argv[1], "rb"); if (!file) return 2;
    std::uint64_t values[3]{};
    for (;;) {
        const auto read = std::fread(values, sizeof(values[0]), 3, file);
        if (!read && std::feof(file)) break;
        if (read != 3 || std::putchar(detail::within(values[0], values[1], values[2]) ? '1' : '0') == EOF) return 3;
    }
    if (std::fclose(file)) return 4;
    pyobfuscator::native::measurement::Data data{};
    data.read_started = 100; data.read_completed = 150; data.frequency = 1000000000;
    const observer::Policy bounded{observer::Mode::periodic_bounded_age, 75, 60};
    if (detail::interval(data, bounded, {150, data.frequency}) != observer::Status::ok ||
        detail::interval(data, bounded, {200, data.frequency}) != observer::Status::expired ||
        detail::interval(data, bounded, {149, data.frequency}) != observer::Status::clock_failed ||
        detail::interval(data, bounded, {150, data.frequency + 1}) != observer::Status::clock_failed ||
        detail::interval(data, {observer::Mode::per_use, 1000, 49}, {150, data.frequency}) != observer::Status::scan_expired ||
        detail::valid_policy({observer::Mode::per_use, 0, 1}) ||
        detail::valid_policy({observer::Mode::periodic_bounded_age, 1, 0}) ||
        detail::valid_policy({observer::Mode::once_per_instance, 1, 0}) ||
        detail::valid_policy({static_cast<observer::Mode>(3), 1, 1}) ||
        !detail::valid_policy({observer::Mode::once_per_instance, 0, 0})) return 5;
    return 0;
}
