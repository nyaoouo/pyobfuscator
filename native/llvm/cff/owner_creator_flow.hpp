#pragma once

#include "owner_reader_bindings.hpp"
#include "llvm/Support/JSON.h"

#include <set>

namespace pyobfuscator::native::cff {
class OwnerCreatorSeal {
public:
    OwnerCreatorSeal(const llvm::Module &, const std::set<std::string> &selected);
    bool empty() const { return creators_.empty(); }
    llvm::json::Object verify(const llvm::Module &) const;

private:
    struct Creator {
        const llvm::Function *function = nullptr;
        OwnerReaderBinding binding;
    };
    std::vector<Creator> creators_;
};
}
