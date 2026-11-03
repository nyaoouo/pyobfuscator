#pragma once

#include <set>
#include <string>
#include <vector>

#include "llvm/ADT/StringRef.h"

namespace llvm { class BasicBlock; class Function; }
namespace pyobfuscator::native::cff {
class RegionScope {
public:
    RegionScope(llvm::Function &, llvm::StringRef entry, llvm::StringRef exit);
    bool contains(const llvm::BasicBlock &) const;
    void adopt(llvm::BasicBlock &);
    std::vector<llvm::BasicBlock *> bodies(llvm::Function &) const;
    llvm::BasicBlock *entry() const { return entry_; }
    llvm::BasicBlock *exit() const { return exit_; }
    const std::string &entry_name() const { return entry_name_; }
    const std::string &exit_name() const { return exit_name_; }
private:
    const llvm::Function *owner_;
    llvm::BasicBlock *entry_ = nullptr, *exit_ = nullptr;
    std::string entry_name_, exit_name_;
    std::set<const llvm::BasicBlock *> members_;
};
}
