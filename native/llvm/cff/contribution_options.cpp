#include "contribution_options.hpp"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
[[noreturn]] void invalid(const char *message) {
    llvm::report_fatal_error(llvm::Twine("native contribution options: ") + message);
}
}
ContributionOverride read_contribution_options(const llvm::json::Value &value) {
    const auto *object = value.getAsObject();
    if (object == nullptr) invalid("expected an object");
    ContributionOverride result;
    for (const auto &field : *object)
        if (field.first != "selection" && field.first != "minimum_edges" && field.first != "minimum_percent" && field.first != "maximum_edges")
            invalid("unknown field");
    if (const auto *field = object->get("selection")) {
        const auto name = field->getAsString();
        if (!name || (*name != "explicit-points" && *name != "original-edges")) invalid("unknown selection");
        result.selection = *name == "original-edges" ? ContributionSelection::original_edges : ContributionSelection::explicit_points;
    }
    const auto number = [&](const char *name, std::optional<unsigned> &destination, unsigned low, unsigned high) {
        const auto *field = object->get(name);
        if (field == nullptr) return;
        const auto amount = field->getAsInteger();
        if (!amount || *amount < low || *amount > high) invalid("numeric requirement is outside its bound");
        destination = static_cast<unsigned>(*amount);
    };
    number("minimum_edges", result.minimum_edges, 0, 65536);
    number("minimum_percent", result.minimum_percent, 0, 100);
    number("maximum_edges", result.maximum_edges, 0, 65536);
    return result;
}
void apply_contribution_options(ContributionOptions &options, const ContributionOverride &override) {
    if (override.selection) options.selection = *override.selection;
    if (override.minimum_edges) options.minimum_edges = *override.minimum_edges;
    if (override.minimum_percent) options.minimum_percent = *override.minimum_percent;
    if (override.maximum_edges) options.maximum_edges = *override.maximum_edges;
}
llvm::json::Object describe_contribution_options(const ContributionOptions &options) {
    return llvm::json::Object{{"selection", options.selection == ContributionSelection::original_edges ? "original-edges" : "explicit-points"},
        {"minimum_edges", options.minimum_edges}, {"minimum_percent", options.minimum_percent}, {"maximum_edges", options.maximum_edges}};
}
}
