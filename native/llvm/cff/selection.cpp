#include "pipeline.hpp"

#include "cff.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {

std::set<std::string> names(llvm::StringRef input) {
    if (input.empty()) return {};
    llvm::SmallVector<llvm::StringRef> values;
    input.split(values, ',', -1, true);
    std::set<std::string> result;
    for (const auto value : values) {
        if (value.empty() || value.trim() != value || !result.insert(value.str()).second)
            llvm::report_fatal_error("native CFF function list has an empty, padded, or duplicate name");
    }
    return result;
}

}  // namespace

Selection resolve_selection(const llvm::Module &module, const PipelineOptions &options,
                             const RecipeConfiguration &configuration) {
    if (!options.function.empty() && !options.functions.empty())
        llvm::report_fatal_error("use only one native CFF function selection option");
    Selection result;
    result.functions = names(options.functions.empty() ? options.function : options.functions);
    result.deep = names(options.deep_functions);
    if (options.markers) result.markers = collect_marked_functions(module);
    if (!options.requests_input.empty()) result.requests = read_request_manifest(options.requests_input);
    for (const auto &specification : options.regions) {
        llvm::SmallVector<llvm::StringRef> parts;
        llvm::StringRef(specification).split(parts, ':', -1, true);
        if (parts.size() != 3 || parts[0].empty() || parts[1].empty() || parts[2].empty() ||
            parts[0].trim() != parts[0] || parts[1].trim() != parts[1] || parts[2].trim() != parts[2] ||
            !result.regions.emplace(parts[0].str(), RegionNames{parts[1].str(), parts[2].str()}).second)
            llvm::report_fatal_error("native CFF region needs a unique function:entry:exit specification");
    }
    for (const auto &[name, request] : result.requests) {
        result.functions.insert(name);
        if (!request.marker.empty() && !result.markers.count(name)) result.markers[name] = request.marker;
    }
    for (const auto &[name, marker] : result.markers) result.functions.insert(name);
    for (const auto &[name, region] : result.regions) result.functions.insert(name);
    for (const auto &[name, override] : configuration.functions) result.functions.insert(name);
    for (const auto &[marker, override] : configuration.markers) {
        bool matched = false;
        for (const auto &[name, label] : result.markers) matched |= marker == label;
        if (!matched) llvm::report_fatal_error(
            llvm::StringRef("native CFF marker override matched no functions: " + marker));
    }
    for (const auto &name : result.deep) {
        if (!result.functions.count(name)) llvm::report_fatal_error(
            llvm::StringRef("deep CFF function is not selected: " + name));
        if (result.regions.count(name)) llvm::report_fatal_error(
            llvm::StringRef("region CFF conflicts with deep function selection: " + name));
    }
    if (result.functions.empty())
        llvm::report_fatal_error("native CFF requires explicit functions or source markers");
    return result;
}

}  // namespace
