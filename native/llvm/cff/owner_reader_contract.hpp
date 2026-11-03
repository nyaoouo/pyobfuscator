#pragma once

#include "owner_reader_bindings.hpp"
#include "llvm/Support/JSON.h"

#include <set>

namespace pyobfuscator::native::cff {
class OwnerReaderSeal {
public:
    OwnerReaderSeal(const llvm::Module &, const std::set<std::string> &selected);
    bool empty() const { return bindings_.empty(); }
    llvm::json::Object verify(const llvm::Module &) const;
private:
    std::vector<OwnerReaderBinding> bindings_;
    std::vector<unsigned> reads_;
};
}
