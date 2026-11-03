#include "hybrid_eh.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

llvm::json::Object describe_hybrid_eh(const llvm::Function &function) {
    unsigned invokes = 0, pads = 0, resumes = 0;
    for (const auto &block : function) {
        invokes += llvm::isa<llvm::InvokeInst>(block.getTerminator());
        resumes += llvm::isa<llvm::ResumeInst>(block.getTerminator());
        pads += block.isLandingPad();
    }
    return llvm::json::Object{{"requested_model", "windows-gnu-cxx-landingpad"},
        {"full_function_coverage", false}, {"preserved_exceptional_edges", invokes},
        {"transformed_exceptional_edges", 0}, {"normal_return_gates", invokes},
        {"landing_pads", pads}, {"resume_sites", resumes}, {"ir_boundary_contract_verified", false},
        {"ir_flow_graph_verified", false}};
}

}  // namespace pyobfuscator::native::cff
