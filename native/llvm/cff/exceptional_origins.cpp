#include "exceptional_origins.hpp"
#include "site_report.hpp"

#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {

ExceptionalOrigins::ExceptionalOrigins(const llvm::Function &function)
    : owner_(&function), personality_(function.hasPersonalityFn() ? function.getPersonalityFn() : nullptr) {
    for (const auto &block : function) {
        if (const auto *invoke = llvm::dyn_cast<llvm::InvokeInst>(block.getTerminator()))
            edges_.push_back({invoke, invoke->getUnwindDest()});
        if (const auto *pad = llvm::dyn_cast<llvm::LandingPadInst>(&*block.getFirstNonPHIIt())) {
            Pad record{pad, &block, pad->isCleanup(), {}};
            for (unsigned index = 0; index < pad->getNumClauses(); ++index) record.clauses.push_back(pad->getClause(index));
            pads_.push_back(std::move(record));
        }
    }
}

std::string ExceptionalOrigins::replace(const llvm::InvokeInst &from, const llvm::InvokeInst &to) {
    for (auto &edge : edges_) if (edge.current == &from) {
        if (to.getFunction() != owner_ || to.getUnwindDest() != edge.unwind)
            return "framed invoke changed its source exception target";
        edge.current = &to;
        return {};
    }
    return "framed invoke has no original exception owner";
}

std::string ExceptionalOrigins::check(const llvm::Function &function) const {
    if (&function != owner_ || (function.hasPersonalityFn() ? function.getPersonalityFn() : nullptr) != personality_)
        return "exception origin personality or function changed";
    std::set<const llvm::InvokeInst *> invokes;
    std::set<const llvm::LandingPadInst *> pads;
    for (const auto &block : function) {
        if (const auto *invoke = llvm::dyn_cast<llvm::InvokeInst>(block.getTerminator())) invokes.insert(invoke);
        if (const auto *pad = llvm::dyn_cast<llvm::LandingPadInst>(&*block.getFirstNonPHIIt())) pads.insert(pad);
    }
    if (invokes.size() != edges_.size() || pads.size() != pads_.size())
        return "exception origin inventory changed";
    for (const auto &edge : edges_)
        if (!invokes.count(edge.current) || edge.current->getUnwindDest() != edge.unwind)
            return "exception origin unwind target changed or its invoke disappeared";
    for (const auto &pad : pads_) {
        if (!pads.count(pad.instruction) || pad.instruction->getParent() != pad.header ||
            pad.instruction->isCleanup() != pad.cleanup || pad.instruction->getNumClauses() != pad.clauses.size())
            return "exception origin landingpad contract changed";
        for (unsigned index = 0; index < pad.clauses.size(); ++index)
            if (pad.instruction->getClause(index) != pad.clauses[index]) return "exception origin landingpad clause changed";
    }
    return {};
}

ExceptionalOrigins &SiteCoverage::exceptional_origins() { return exceptional_; }

}  // namespace pyobfuscator::native::cff
