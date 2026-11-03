#include "pipeline.hpp"

#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff {

void write_json_report(llvm::StringRef path, llvm::json::Object root) {
    if (path.empty()) return;
    std::error_code error;
    llvm::raw_fd_ostream output(path, error, llvm::sys::fs::OF_Text);
    if (error) llvm::report_fatal_error(
        llvm::StringRef("cannot write native CFF report: " + error.message()));
    output << llvm::json::Value(std::move(root)) << '\n';
    output.flush();
    if (output.has_error()) llvm::report_fatal_error("failed to flush native CFF report");
}

}  // namespace pyobfuscator::native::cff
