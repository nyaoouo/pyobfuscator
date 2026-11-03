#include "plan.hpp"

#include "../cff/cff.hpp"
#include "../cff/pipeline.hpp"
#include "../cff/hybrid_eh.hpp"

#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::archive {

void reject_pending_plan(const llvm::Module &module) {
    if (module.getNamedMetadata("pyobf.archive.pending") != nullptr ||
        module.getNamedMetadata("pyobf.archive.records") != nullptr)
        llvm::report_fatal_error("native archive plan is pending wrapper and state-key materialization");
    for (const auto &function : module)
        if (function.hasFnAttribute("pyobf.archive.pending") ||
            function.getName().starts_with("__pyobf_archive_pending_"))
            llvm::report_fatal_error("native archive plan has an unresolved acquisition gate");
}

void create_plan(llvm::Module &module, const cff::PipelineOptions &options,
                    const std::string &output_path) {
    if (output_path.empty()) llvm::report_fatal_error("native archive plan needs an explicit private output path");
    reject_pending_plan(module);
    if (module.getNamedMetadata("pyobf.archive.prepared") != nullptr ||
        module.getNamedMetadata("pyobf.archive.empty") != nullptr)
        llvm::report_fatal_error("native archive plan is already materialized");
    if (module.getDataLayoutStr().empty() ||
        (module.getDataLayout().getPointerSizeInBits() != 32 && module.getDataLayout().getPointerSizeInBits() != 64))
        llvm::report_fatal_error("native archive plan needs an explicit 32-bit or 64-bit data layout");
    for (const auto &value : module.global_values())
        if (value.getName().starts_with("__pyobf_archive_"))
            llvm::report_fatal_error("native archive reserved name already exists; self-archiving is unsupported");
    const auto configuration = cff::read_recipe_configuration(options.configuration);
    const auto selection = cff::resolve_selection(module, options, configuration);
    if (!selection.regions.empty()) llvm::report_fatal_error("native archive planning requires whole-function scopes");
    for (const auto &name : selection.functions) {
        const auto *function = module.getFunction(name);
        if (function == nullptr) llvm::report_fatal_error("native archive selected function is missing");
    }
    std::set<std::string> archive_functions;
    std::set<std::string> integer_exempt;
    for (const auto &name : selection.functions) {
        const auto marker = selection.markers.find(name);
        const auto recipe = cff::resolve_recipe(configuration, name,
            marker == selection.markers.end() ? llvm::StringRef{} : llvm::StringRef(marker->second),
            options.strategy, selection.deep.count(name), false, options.seed);
        if (!options.configuration.empty() && recipe.enabled("integer-literals")) integer_exempt.insert(name);
        if (!options.configuration.empty() && !recipe.enabled("constant-archive")) continue;
        archive_functions.insert(name);
        if (const auto reason = cff::validate_configured(*module.getFunction(name), recipe); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef("native archive source: " + reason));
    }
    auto records = analyze_uses(module, archive_functions, integer_exempt);
    std::string contents;
    llvm::raw_string_ostream stream(contents);
    stream << llvm::json::Value(private_plan(records)) << '\n';
    const auto hash = llvm::SHA256::hash(llvm::ArrayRef<std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(contents.data()), contents.size()));
    std::error_code error;
    llvm::raw_fd_ostream output(output_path, error, llvm::sys::fs::OF_None);
    if (error) llvm::report_fatal_error("cannot write native archive private plan");
    output << contents;
    output.flush();
    if (output.has_error()) llvm::report_fatal_error("cannot flush native archive private plan");
    instrument_plan(module, records);
    auto &context = module.getContext();
    module.getOrInsertNamedMetadata("pyobf.archive.pending")->addOperand(llvm::MDNode::get(context,
        {llvm::MDString::get(context, "compiler-ir-v2"), llvm::MDString::get(context, llvm::toHex(hash))}));
}

}  // namespace pyobfuscator::native::archive
