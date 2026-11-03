#pragma once

#include "llvm/Support/JSON.h"

#include <set>
#include <string>

namespace llvm { class Module; }
namespace pyobfuscator::native::cff {
void verify_post_child_source(const llvm::Module &);
void verify_post_child(const llvm::Module &);
class PostChildSeal {
public:
    PostChildSeal(const llvm::Module &, const std::set<std::string> &selected, bool mixed = false);
    bool empty() const { return !active_; }
    llvm::json::Object verify(const llvm::Module &) const;

private:
    bool active_ = false;
    bool mixed_ = false;
};
}
