#include "environment_internal.hpp"

#include <string_view>

namespace pyobfuscator::native::environment {

namespace {

const DetectorDefinition *find_detector(DetectorCatalog detectors,
                                        std::string_view name) noexcept {
    for (std::size_t index = 0; index < detectors.count; ++index) {
        if (name == detectors.entries[index].name) {
            return &detectors.entries[index];
        }
    }
    return nullptr;
}

}  // namespace

Report inspect(const char *comma_separated_names) noexcept {
    Report report;
    if (comma_separated_names == nullptr || *comma_separated_names == '\0') {
        return report;
    }
    const auto detectors = catalog();
    const DetectorDefinition *selected[max_detectors]{};
    std::size_t selected_count = 0;
    std::string_view remaining(comma_separated_names);
    while (!remaining.empty()) {
        const auto separator = remaining.find(',');
        const auto name = remaining.substr(0, separator);
        const auto *detector = find_detector(detectors, name);
        if (detector == nullptr || selected_count == max_detectors) {
            return report;
        }
        for (std::size_t index = 0; index < selected_count; ++index) {
            if (name == selected[index]->name) {
                return report;
            }
        }
        selected[selected_count++] = detector;
        if (separator == std::string_view::npos) {
            break;
        }
        remaining.remove_prefix(separator + 1);
        if (remaining.empty()) {
            return report;
        }
    }
    for (std::size_t index = 0; index < selected_count; ++index) {
        const auto result = selected[index]->inspect();
        report.observations[report.count++] = {selected[index]->name, result};
        if (result == Result::triggered) {
            report.overall = Result::triggered;
        } else if (result == Result::unavailable && report.overall != Result::triggered) {
            report.overall = Result::unavailable;
        } else if (result == Result::clear && report.count == 1) {
            report.overall = Result::clear;
        }
    }
    report.valid = true;
    return report;
}

}  // namespace pyobfuscator::native::environment
