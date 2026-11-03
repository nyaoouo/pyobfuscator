#include "pipeline.hpp"
#include "generated_ownership.hpp"
#include "path_fold_sites.hpp"
#include "contribution_gate.hpp"
#include "owner_post_child_flow.hpp"
#include "../archive/plan.hpp"
#include "../archive/bindings.hpp"

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Support/CommandLine.h"

namespace {

llvm::cl::opt<std::string> selected_function("pyobf-cff-function", llvm::cl::init(""));
llvm::cl::opt<std::string> selected_functions("pyobf-cff-functions", llvm::cl::init(""));
llvm::cl::opt<std::string> deep_functions("pyobf-cff-deep-functions", llvm::cl::init(""));
llvm::cl::list<std::string> selected_regions("pyobf-cff-region", llvm::cl::ZeroOrMore);
llvm::cl::opt<std::string> strategy_name("pyobf-cff-strategy", llvm::cl::init("relative-tree"));
llvm::cl::opt<std::string> report_path("pyobf-cff-report", llvm::cl::init(""));
llvm::cl::opt<std::string> requests_output("pyobf-cff-requests-output", llvm::cl::init(""));
llvm::cl::opt<std::string> requests_input("pyobf-cff-requests-input", llvm::cl::init(""));
llvm::cl::opt<std::string> configuration("pyobf-cff-config",
    llvm::cl::desc("Versioned native recipe JSON"), llvm::cl::init(""));
llvm::cl::opt<std::string> private_map("pyobf-cff-private-map",
    llvm::cl::desc("Opt-in private site/source mapping JSON"), llvm::cl::init(""));
llvm::cl::opt<std::string> edge_plan_output("pyobf-cff-edge-plan-output",
    llvm::cl::desc("Private plan of retained original edges before CFF"), llvm::cl::init(""));
llvm::cl::opt<std::string> edge_plan_input("pyobf-cff-edge-plan-input",
    llvm::cl::desc("Require the exact retained original-edge plan during CFF"), llvm::cl::init(""));
llvm::cl::opt<std::string> edge_ir_input("pyobf-cff-edge-ir-input",
    llvm::cl::desc("Exact retained IR path for original-edge plan output alias checks"), llvm::cl::init(""));
llvm::cl::opt<std::string> edge_owners("pyobf-cff-edge-owners",
    llvm::cl::desc("Canonical POST owner subset for the opt-in two-owner original-edge plan"), llvm::cl::init(""));
llvm::cl::opt<std::string> contribution_input("pyobf-cff-contribution-input",
    llvm::cl::desc("Private owned-context contribution reference; never a runtime expected-value lookup"), llvm::cl::init(""));
llvm::cl::opt<std::string> archive_plan_output("pyobf-archive-plan-output",
    llvm::cl::desc("Private typed archive plan output; intermediate IR needs later materialization"), llvm::cl::init(""));
llvm::cl::opt<std::string> archive_bindings("pyobf-archive-bindings",
    llvm::cl::desc("Private compiler archive binding manifest"), llvm::cl::init(""));
llvm::cl::opt<unsigned> build_seed("pyobf-cff-seed", llvm::cl::init(1));
llvm::cl::opt<bool> include_markers("pyobf-cff-markers", llvm::cl::init(true));
llvm::cl::opt<bool> require_decision_flow("pyobf-cff-require-decision-flow", llvm::cl::init(false));

pyobfuscator::native::cff::PipelineOptions options() {
    return {selected_function, selected_functions, deep_functions,
            {selected_regions.begin(), selected_regions.end()}, strategy_name, report_path,
            requests_input, requests_output, configuration, private_map, build_seed,
            include_markers, require_decision_flow, contribution_input, edge_plan_input,
            edge_ir_input, edge_owners};
}

class CffPass : public llvm::PassInfoMixin<CffPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::cff::run_pipeline(module, options());
        return llvm::PreservedAnalyses::none();
    }
};

class PathFoldVerifyPass : public llvm::PassInfoMixin<PathFoldVerifyPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        for (const auto &function : module)
            if (const auto reason = pyobfuscator::native::cff::validate_path_fold(function); !reason.empty())
                llvm::report_fatal_error(llvm::StringRef(reason));
        return llvm::PreservedAnalyses::all();
    }
};

class ContributionVerifyPass : public llvm::PassInfoMixin<ContributionVerifyPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        for (const auto &function : module)
            if (const auto reason = pyobfuscator::native::cff::validate_contribution_gates(function); !reason.empty())
                llvm::report_fatal_error(llvm::StringRef(reason));
        return llvm::PreservedAnalyses::all();
    }
};

class PostChildVerifyPass : public llvm::PassInfoMixin<PostChildVerifyPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::cff::verify_post_child(module);
        return llvm::PreservedAnalyses::all();
    }
};

class PostChildSourceVerifyPass : public llvm::PassInfoMixin<PostChildSourceVerifyPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::cff::verify_post_child_source(module);
        return llvm::PreservedAnalyses::all();
    }
};

class UntransformedOwnershipPass : public llvm::PassInfoMixin<UntransformedOwnershipPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::cff::write_untransformed_inventory(module, report_path);
        return llvm::PreservedAnalyses::all();
    }
};

class CffRequestPass : public llvm::PassInfoMixin<CffRequestPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::cff::collect_pipeline_requests(module, options());
        return llvm::PreservedAnalyses::none();
    }
};

class CffEdgePlanPass : public llvm::PassInfoMixin<CffEdgePlanPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::cff::write_original_edge_plan(module, options(), edge_plan_output);
        return llvm::PreservedAnalyses::all();
    }
};

class CffEdgePlanVerifyPass : public llvm::PassInfoMixin<CffEdgePlanVerifyPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::cff::verify_original_edge_plan(module, options(), edge_plan_input);
        return llvm::PreservedAnalyses::all();
    }
};

class ArchivePlanPass : public llvm::PassInfoMixin<ArchivePlanPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::archive::create_plan(module, options(), archive_plan_output);
        return llvm::PreservedAnalyses::none();
    }
};

class ArchiveMaterializePass : public llvm::PassInfoMixin<ArchiveMaterializePass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &module, llvm::ModuleAnalysisManager &) {
        pyobfuscator::native::archive::materialize(module, archive_bindings);
        return llvm::PreservedAnalyses::none();
    }
};

}  // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "pyobf-native-cff", LLVM_VERSION_STRING,
            [](llvm::PassBuilder &builder) {
                builder.registerPipelineParsingCallback(
                    [](llvm::StringRef name, llvm::ModulePassManager &manager,
                       llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                        if (name == "pyobf-native-cff") manager.addPass(CffPass());
                        else if (name == "pyobf-native-untransformed-ownership") manager.addPass(UntransformedOwnershipPass());
                        else if (name == "pyobf-native-cff-requests") manager.addPass(CffRequestPass());
                        else if (name == "pyobf-native-cff-edge-plan") manager.addPass(CffEdgePlanPass());
                        else if (name == "pyobf-native-cff-edge-plan-verify") manager.addPass(CffEdgePlanVerifyPass());
                        else if (name == "pyobf-native-archive-plan") manager.addPass(ArchivePlanPass());
                        else if (name == "pyobf-native-archive-materialize") manager.addPass(ArchiveMaterializePass());
                        else if (name == "pyobf-native-path-fold-verify") manager.addPass(PathFoldVerifyPass());
                        else if (name == "pyobf-native-contribution-verify") manager.addPass(ContributionVerifyPass());
                        else if (name == "pyobf-native-post-child-verify") manager.addPass(PostChildVerifyPass());
                        else if (name == "pyobf-native-post-child-source-verify") manager.addPass(PostChildSourceVerifyPass());
                        else return false;
                        return true;
                    });
            }};
}
