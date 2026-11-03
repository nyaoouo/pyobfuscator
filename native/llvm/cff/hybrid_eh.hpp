#pragma once

#include <set>
#include <string>
#include <vector>

#include "llvm/Support/JSON.h"

namespace llvm {
class AllocaInst;
class BasicBlock;
class Constant;
class Function;
class InvokeInst;
class LandingPadInst;
class Value;
}

namespace pyobfuscator::native::cff {

class SiteCoverage;
class CfgOrigins;
class ContributionEdgePlan;
struct StateLayout;

struct HybridEhPlan {
    struct Invoke {
        llvm::InvokeInst *instruction;
        llvm::BasicBlock *normal, *unwind, *gateway;
    };
    struct Pad {
        llvm::LandingPadInst *instruction;
        llvm::BasicBlock *header, *continuation;
        bool cleanup;
        std::vector<llvm::Constant *> clauses;
    };
    llvm::Constant *personality = nullptr;
    llvm::AllocaInst *unwind_correction = nullptr;
    std::vector<Invoke> invokes;
    std::vector<Pad> pads;
    std::set<const llvm::BasicBlock *> boundaries;
};

std::string validate_hybrid_eh(const llvm::Function &function);
bool hybrid_component_supported(llvm::StringRef name);
HybridEhPlan prepare_hybrid_eh(llvm::Function &function, SiteCoverage &coverage);
HybridEhPlan prepare_hybrid_eh_edges(llvm::Function &, CfgOrigins &, ContributionEdgePlan *);
std::string bind_hybrid_eh(HybridEhPlan &plan, llvm::Function &function,
                           const StateLayout &layout, llvm::Value *state_slot,
                           llvm::BasicBlock *dispatch);
std::string verify_hybrid_eh(const HybridEhPlan &plan, const llvm::Function &function);
llvm::json::Object describe_hybrid_eh(const llvm::Function &function);

}  // namespace pyobfuscator::native::cff
