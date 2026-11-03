#include "measured_contribution_cases.hpp"

#include <cstdio>
#include <cstdlib>

namespace native = pyobfuscator::native;
namespace measured = native::contribution::measured;
namespace {
void require(bool value, const char *why) {
    if (!value) { std::fprintf(stderr, "measured contribution: %s\n", why); std::exit(1); }
}
}
void check_contributions(const native::path_fold::Storage &fold, const native::release::Record &record,
        const native::measurement::observer::Snapshot &snapshot, const std::vector<std::uint8_t> &expected, bool correct) {
    require(expected.size() == 4 * 28, "four independent contribution vectors");
    for (unsigned offset = 0; offset != expected.size(); offset += 28) {
        std::uint32_t row[7]{};
        for (unsigned index = 0; index != 7; ++index)
            for (unsigned byte = 0; byte != 4; ++byte)
                row[index] |= std::uint32_t(expected[offset + index * 4 + byte]) << (byte * 8);
        const native::contribution::Site site{row[1], row[2], row[3], row[4], row[5]};
        const auto result = measured::derive(fold, record, snapshot, row[0], site);
        if (correct) {
            require(result.status == measured::Status::ok && result.material.status == native::release::measured::Status::ok &&
                result.value.status == native::BootstrapContextStatus::ok && result.value.word == row[6] &&
                result.observation.code == native::measurement::observer::Status::ok, "independent actual material-to-word result");
        } else {
            require(result.value.status != native::BootstrapContextStatus::ok || result.value.word != row[6],
                "changed actual material recovered the expected contribution");
            if (result.status != measured::Status::ok) require(result.value.word == 0, "failure published a contribution word");
        }
    }
    if (correct) {
        const auto invalid = measured::derive(fold, record, snapshot, 0, {1, 1, 1, 1, 0});
        require(invalid.status == measured::Status::derivation_failed &&
            invalid.value.status == native::BootstrapContextStatus::invalid_request && invalid.value.word == 0,
            "invalid request lost derivation provenance");
    }
}
