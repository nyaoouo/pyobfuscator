#include "generated_ownership.hpp"
#include "pipeline.hpp"
#include "call_frames.hpp"
#include "call_preparation.hpp"
#include "indexed_locals.hpp"
#include "reference_routes.hpp"
#include "contribution_gate.hpp"
#include "bogus_controls.hpp"
#include "../archive/plan.hpp"

#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
void write_untransformed_inventory(const llvm::Module &module, llvm::StringRef path) {
    if (path.empty()) llvm::report_fatal_error("untransformed ownership needs a private report path");
    reject_contribution_artifacts(module);
    reject_bogus_control_artifacts(module);
    reject_local_artifacts(module);
    reject_preparation_artifacts(module);
    reject_call_frame_artifacts(module);
    reject_reference_artifacts(module);
    archive::reject_pending_plan(module);
    if (module.getNamedMetadata("pyobf.archive.prepared") || module.getNamedMetadata("pyobf.archive.empty"))
        llvm::report_fatal_error("untransformed ownership refuses prepared archive code");
    llvm::json::Array functions;
    for (const auto &function : module) {
        if (function.hasFnAttribute("pyobf.cff.transformed") || function.hasFnAttribute("pyobf.archive.wrapper"))
            llvm::report_fatal_error("untransformed ownership refuses transformed/generated code");
        functions.push_back(llvm::json::Object{{"function", function.getName()}, {"selected", false},
            {"requested", false}, {"retained", !function.isDeclaration()},
            {"status", function.isDeclaration() ? "declaration" : "unselected"}});
    }
    auto ownership = generated_ownership(module, {}, functions);
    write_json_report(path, llvm::json::Object{{"schema_version", 2}, {"module", module.getModuleIdentifier()},
        {"domain", "untransformed"}, {"llvm_version", LLVM_VERSION_STRING},
        {"target_triple", module.getTargetTriple().str()}, {"data_layout", module.getDataLayoutStr()},
        {"generated_ownership", std::move(ownership)}, {"functions", std::move(functions)}});
}
}
