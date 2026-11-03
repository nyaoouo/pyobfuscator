#pragma once

#include "recipe.hpp"
#include "request_manifest.hpp"
#include "contribution_contract.hpp"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace llvm {
class Module;
}

namespace pyobfuscator::native::cff {

struct PipelineOptions {
    std::string function;
    std::string functions;
    std::string deep_functions;
    std::vector<std::string> regions;
    std::string strategy;
    std::string report;
    std::string requests_input;
    std::string requests_output;
    std::string configuration;
    std::string private_map;
    unsigned seed;
    bool markers;
    bool require_decision_flow;
    std::string contribution_input;
    std::string original_edge_plan_input;
    std::string original_edge_ir_input;
    std::string original_edge_owners;
};

struct RegionNames {
    std::string entry;
    std::string exit;
};

struct Selection {
    std::set<std::string> functions;
    std::set<std::string> deep;
    std::map<std::string, RegionNames> regions;
    std::map<std::string, std::string> markers;
    Requests requests;
};

Selection resolve_selection(const llvm::Module &module, const PipelineOptions &options,
                             const RecipeConfiguration &configuration);
void run_pipeline(llvm::Module &module, const PipelineOptions &options);
void collect_pipeline_requests(llvm::Module &module, const PipelineOptions &options);
void write_original_edge_plan(llvm::Module &module, const PipelineOptions &options,
                              llvm::StringRef output);
std::string verify_original_edge_plan(llvm::Module &module, const PipelineOptions &options,
                                      llvm::StringRef input);
void write_json_report(llvm::StringRef path, llvm::json::Object root);

}  // namespace pyobfuscator::native::cff
