#include "region_scope.hpp"

#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
RegionScope::RegionScope(llvm::Function &function, llvm::StringRef entry, llvm::StringRef exit)
    : owner_(&function), entry_name_(entry.str()), exit_name_(exit.str()) {
    for (auto &body : function) {
        if (body.getName() == entry) entry_ = &body;
        if (body.getName() == exit) exit_ = &body;
    }
    if (entry_ == nullptr || exit_ == nullptr || entry_ == exit_) return;
    std::vector<llvm::BasicBlock *> pending{entry_};
    while (!pending.empty()) {
        auto *body = pending.back(); pending.pop_back();
        if (body == exit_ || !members_.insert(body).second) continue;
        for (auto *next : llvm::successors(body)) pending.push_back(next);
    }
}
bool RegionScope::contains(const llvm::BasicBlock &body) const { return members_.count(&body); }
void RegionScope::adopt(llvm::BasicBlock &body) {
    if (body.getParent() != owner_ || &body == exit_) llvm::report_fatal_error("region adopted a foreign/exit body");
    members_.insert(&body);
}
std::vector<llvm::BasicBlock *> RegionScope::bodies(llvm::Function &function) const {
    if (&function != owner_) llvm::report_fatal_error("region owner changed");
    std::vector<llvm::BasicBlock *> result;
    for (auto &body : function) if (contains(body)) result.push_back(&body);
    return result;
}
}
