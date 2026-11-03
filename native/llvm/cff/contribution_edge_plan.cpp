#include "pipeline.hpp"
#include "site_provenance.hpp"

#include <cstdint>
#include <filesystem>
#include <set>
#include <string>

#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff {
namespace {

[[noreturn]] void invalid(llvm::StringRef reason) {
    llvm::report_fatal_error(llvm::Twine("native original-edge plan: ") + reason);
}

std::string sha256(llvm::StringRef source) {
    const auto bytes = llvm::ArrayRef<std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(source.data()), source.size());
    return llvm::toHex(llvm::SHA256::hash(bytes), true);
}

bool aliases(llvm::StringRef left, llvm::StringRef right) {
    if (right.empty()) return false;
    std::error_code left_error, right_error, equivalent_error;
    const auto lhs = std::filesystem::weakly_canonical(std::filesystem::path(left.str()), left_error);
    const auto rhs = std::filesystem::weakly_canonical(std::filesystem::path(right.str()), right_error);
    if (left_error || right_error) invalid("cannot compare plan output with an input path");
    if (lhs == rhs) return true;
    const bool same = std::filesystem::equivalent(lhs, rhs, equivalent_error);
    return !equivalent_error && same;
}

llvm::json::Object post_two_plan(llvm::Module &module, const PipelineOptions &options,
                                 const RecipeConfiguration &configuration, const Selection &selection) {
    constexpr llvm::StringRef pair = "pyobf_demo_bound_compute,pyobf_demo_protection_wrapper";
    if (options.original_edge_owners != pair)
        invalid("POST owners must be the exact canonical role pair");
    for (const auto &selected : selection.functions) {
        if (selected == "pyobf_demo_bound_compute" || selected == "pyobf_demo_protection_wrapper") continue;
        const auto marker = selection.markers.find(selected);
        const auto recipe = resolve_recipe(configuration, selected,
            marker == selection.markers.end() ? llvm::StringRef{} : llvm::StringRef(marker->second),
            options.strategy, selection.deep.count(selected), selection.regions.count(selected), options.seed);
        if (recipe.enabled("runtime-contribution") &&
                recipe.contribution_options.selection == ContributionSelection::original_edges)
            invalid("extra selected original-edge owner is outside POST role pair");
    }
    llvm::json::Array owners;
    std::set<std::uint32_t> all_labels;
    for (const auto *name : {"pyobf_demo_bound_compute", "pyobf_demo_protection_wrapper"}) {
        if (!selection.functions.count(name) || selection.regions.count(name))
            invalid("POST owner is missing from whole-function selection");
        auto *function = module.getFunction(name);
        if (function == nullptr || function->isDeclaration())
            invalid("selected POST owner definition is absent");
        const auto marker = selection.markers.find(name);
        const auto recipe = resolve_recipe(configuration, name,
            marker == selection.markers.end() ? llvm::StringRef{} : llvm::StringRef(marker->second),
            options.strategy, selection.deep.count(name), false, options.seed);
        if (recipe.strategy != "relative-tree" || recipe.coverage != "whole" ||
                recipe.contribution_options.selection != ContributionSelection::original_edges ||
                recipe.contribution_options.minimum_edges != 3 ||
                recipe.contribution_options.maximum_edges != 8 ||
                recipe.contribution_options.minimum_percent != 100 ||
                !recipe.enabled("runtime-contribution"))
            invalid("POST owners need strict whole bounded original-edge recipes");
        for (const auto *component : {"deduplicate-blocks", "split-blocks", "common-exit"})
            if (recipe.enabled(component)) invalid("normalization component is outside the bounded profile");
        if (function->arg_size() < 2 || !function->getArg(0)->getType()->isPointerTy() ||
                !function->getArg(1)->getType()->isPointerTy() ||
                function->getArg(0)->getType()->getPointerAddressSpace() != 0 ||
                function->getArg(1)->getType()->getPointerAddressSpace() != 0)
            invalid("requires separate owned and measured pointer arguments");
        for (const auto &block : *function)
            for (const auto &instruction : block)
                if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
                    if (const auto *target = llvm::dyn_cast<llvm::Function>(
                            call->getCalledOperand()->stripPointerCastsAndAliases()))
                        if (target->getName() == "pyobf_native_mixed_contribution_site_v1" ||
                                target->getName() == "pyobf_native_measured_contribution_site_v1" ||
                                target->getName() == "pyobf_native_contribution_site_v1")
                            invalid("bounded source-mixed profile cannot contain an explicit contribution marker");
        llvm::json::Array edges;
        std::set<std::uint32_t> labels;
        unsigned sequence = 0;
        unsigned decisions = 0;
        for (const auto &block : *function) {
            const auto *term = block.getTerminator();
            if (term == nullptr || !llvm::isa<llvm::BranchInst, llvm::ReturnInst>(term))
                invalid("bounded profile needs branch or return terminators");
            if (const auto *branch = llvm::dyn_cast<llvm::BranchInst>(term)) {
                if (branch->isConditional()) {
                    if (branch->getSuccessor(0) == branch->getSuccessor(1))
                        invalid("source-mixed decision needs distinct normal successors");
                    ++decisions;
                }
                const auto origin = instruction_provenance(*term);
                if (origin.empty()) invalid("requires source-retained terminator provenance");
                for (unsigned index = 0; index != branch->getNumSuccessors(); ++index) {
                    const auto id = origin + ":instance:" + std::to_string(sequence) + ":edge:" + std::to_string(index);
                    const auto label = component_seed(recipe.seeds.at("runtime-contribution"), name, id);
                    if (label == 0 || !labels.insert(label).second || !all_labels.insert(label).second)
                        invalid("generated original-edge identity collision");
                    edges.push_back(llvm::json::Object{{"id", id}, {"label", label},
                        {"successor_index", index}});
                }
            }
            ++sequence;
        }
        if (edges.size() < 3 || edges.size() > 8 || decisions == 0)
            invalid("POST owner needs three to eight retained normal edges and a conditional decision");
        owners.push_back(llvm::json::Object{{"owner", name}, {"recipe", describe_recipe(recipe)},
            {"edges", std::move(edges)}});
    }
    std::string input_ir;
    llvm::raw_string_ostream stream(input_ir);
    module.print(stream, nullptr);
    stream.flush();
    return llvm::json::Object{{"schema_version", 2},
        {"profile", "schema4-original-edges-post-two-v1"},
        {"input_ir_encoding", "llvm-module-print-v1"},
        {"input_ir_sha256", sha256(input_ir)}, {"owners", std::move(owners)}};
}

}  // namespace

llvm::json::Object build_original_edge_plan(llvm::Module &module, const PipelineOptions &options) {
    const auto configuration = read_recipe_configuration(options.configuration);
    const auto selection = resolve_selection(module, options, configuration);
    if (!options.original_edge_owners.empty())
        return post_two_plan(module, options, configuration, selection);
    if (selection.functions.size() != 1 || !selection.regions.empty())
        invalid("requires exactly one whole-function owner");
    const auto &name = *selection.functions.begin();
    auto *function = module.getFunction(name);
    if (function == nullptr || function->isDeclaration())
        invalid("selected owner definition is absent");
    const auto marker = selection.markers.find(name);
    const auto recipe = resolve_recipe(configuration, name,
        marker == selection.markers.end() ? llvm::StringRef{} : llvm::StringRef(marker->second),
        options.strategy, selection.deep.count(name), false, options.seed);
    const bool exact_two = recipe.contribution_options.minimum_edges == 2 &&
        recipe.contribution_options.maximum_edges == 2;
    const bool bounded = recipe.contribution_options.minimum_edges == 3 &&
        recipe.contribution_options.maximum_edges == 8;
    if (recipe.strategy != "relative-tree" || recipe.coverage != "whole" ||
            recipe.contribution_options.selection != ContributionSelection::original_edges ||
            recipe.contribution_options.minimum_percent != 100 ||
            (!exact_two && !bounded) ||
            !recipe.enabled("runtime-contribution"))
        invalid("requires strict whole relative-tree two-edge contribution recipe");
    for (const auto *component : {"deduplicate-blocks", "split-blocks", "common-exit"})
        if (recipe.enabled(component)) invalid("normalization component is outside the bounded profile");
    if (function->arg_size() < 2 || !function->getArg(0)->getType()->isPointerTy() ||
            !function->getArg(1)->getType()->isPointerTy())
        invalid("requires separate owned and measured pointer arguments");
    for (const auto &block : *function)
        for (const auto &instruction : block)
            if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
                if (const auto *target = llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCasts()))
                    if (target->getName() == "pyobf_native_mixed_contribution_site_v1" ||
                            target->getName() == "pyobf_native_measured_contribution_site_v1" ||
                            target->getName() == "pyobf_native_contribution_site_v1")
                        invalid("bounded source-mixed profile cannot contain an explicit contribution marker");

    std::string input_ir;
    llvm::raw_string_ostream stream(input_ir);
    module.print(stream, nullptr);
    stream.flush();
    llvm::json::Array edges;
    std::set<std::uint32_t> labels;
    unsigned sequence = 0;
    unsigned decisions = 0;
    for (const auto &block : *function) {
        const auto *term = block.getTerminator();
        if (term == nullptr || !llvm::isa<llvm::BranchInst, llvm::ReturnInst>(term))
            invalid("bounded profile needs branch or return terminators");
        if (auto *branch = llvm::dyn_cast<llvm::BranchInst>(term)) {
            if (branch->isConditional()) {
                if (branch->getSuccessor(0) == branch->getSuccessor(1))
                    invalid("source-mixed decision needs distinct normal successors");
                ++decisions;
            }
            const auto origin = instruction_provenance(*term);
            if (origin.empty()) invalid("requires source-retained terminator provenance");
            for (unsigned index = 0; index != branch->getNumSuccessors(); ++index) {
                const auto id = origin + ":instance:" + std::to_string(sequence) + ":edge:" + std::to_string(index);
                const auto label = component_seed(recipe.seeds.at("runtime-contribution"), name, id);
                if (label == 0 || !labels.insert(label).second)
                    invalid("generated original-edge identity collision");
                edges.push_back(llvm::json::Object{{"id", id}, {"label", label},
                    {"successor_index", index}});
            }
        }
        ++sequence;
    }
    if (exact_two) {
        if (edges.size() != 2 || decisions != 1)
            invalid("needs one conditional decision with exactly two retained normal edges");
        return llvm::json::Object{{"schema_version", 1},
            {"owner", name}, {"input_ir_encoding", "llvm-module-print-v1"},
            {"input_ir_sha256", sha256(input_ir)},
            {"recipe", describe_recipe(recipe)}, {"edges", std::move(edges)}};
    }
    if (edges.size() < 3 || edges.size() > 8 || decisions == 0)
        invalid("bounded source-mixed profile needs three to eight edges and a conditional decision");
    llvm::json::Array owners;
    owners.push_back(llvm::json::Object{{"owner", name}, {"recipe", describe_recipe(recipe)},
        {"edges", std::move(edges)}});
    return llvm::json::Object{{"schema_version", 2},
        {"profile", "schema4-original-edges-bounded-v2"},
        {"input_ir_encoding", "llvm-module-print-v1"},
        {"input_ir_sha256", sha256(input_ir)}, {"owners", std::move(owners)}};
}

void write_original_edge_plan(llvm::Module &module, const PipelineOptions &options,
                              llvm::StringRef output) {
    if (output.empty()) invalid("needs an output path");
    if (options.original_edge_ir_input.empty()) invalid("needs the exact retained IR input path");
    for (const auto &input : {llvm::StringRef(options.original_edge_ir_input),
            llvm::StringRef(options.configuration), llvm::StringRef(options.requests_input),
            llvm::StringRef(options.requests_output), llvm::StringRef(options.contribution_input),
            llvm::StringRef(options.original_edge_plan_input), llvm::StringRef(options.report),
            llvm::StringRef(module.getModuleIdentifier()), llvm::StringRef(module.getSourceFileName())})
        if (aliases(output, input)) invalid("plan output aliases an input");
    write_json_report(output, build_original_edge_plan(module, options));
}

std::string verify_original_edge_plan(llvm::Module &module, const PipelineOptions &options,
                                      llvm::StringRef input) {
    const auto data = llvm::MemoryBuffer::getFile(input);
    if (!data) invalid("cannot read frozen plan input");
    std::string expected;
    llvm::raw_string_ostream stream(expected);
    stream << llvm::json::Value(build_original_edge_plan(module, options)) << '\n';
    stream.flush();
    if ((*data)->getBuffer() != expected)
        invalid("frozen plan differs from exact retained IR and recipe");
    return sha256((*data)->getBuffer());
}

}  // namespace pyobfuscator::native::cff
