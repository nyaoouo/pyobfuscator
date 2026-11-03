#pragma once

#include <map>
#include <string>

#include "llvm/ADT/StringRef.h"
#include "site_report.hpp"

namespace llvm {
class Module;
}

namespace pyobfuscator::native::cff {

struct Request {
    std::string marker;
    bool defined;
    std::vector<RequestedSite> sites;
};

using Requests = std::map<std::string, Request>;

void write_request_manifest(const llvm::Module &module, llvm::StringRef path,
                            const Requests &requests);
Requests read_request_manifest(llvm::StringRef path);

}  // namespace pyobfuscator::native::cff
