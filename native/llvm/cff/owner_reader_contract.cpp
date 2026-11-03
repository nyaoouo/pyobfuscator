#include "owner_reader_contract.hpp"
#include "owner_reader_flow.hpp"

#include "llvm/IR/Function.h"
#include "llvm/Support/ErrorHandling.h"

#include <iomanip>
#include <sstream>

namespace pyobfuscator::native::cff {
namespace {
void checked(const OwnerReaderFlow &flow) {
    if (!flow.error.empty()) llvm::report_fatal_error(llvm::StringRef(flow.error));
}
std::string key_text(std::uint64_t key) {
    std::ostringstream output; output << std::hex << std::setfill('0') << std::setw(16) << key; return output.str();
}
}
OwnerReaderSeal::OwnerReaderSeal(const llvm::Module &module, const std::set<std::string> &selected)
    : bindings_(collect_owner_readers(module)) {
    for (const auto &binding : bindings_) {
        if (!selected.count(binding.capture->getName().str()) || !selected.count(binding.cache->getName().str()))
            llvm::report_fatal_error("owner reader callbacks need complete selected source definitions");
        const auto flow = check_owner_reader_flow(*binding.capture, binding.key, true, true); checked(flow);
        checked(check_owner_reader_flow(*binding.cache, binding.key, false, true)); reads_.push_back(flow.volatile_reads);
    }
}
llvm::json::Object OwnerReaderSeal::verify(const llvm::Module &module) const {
    const auto current = collect_owner_readers(module);
    if (current.size() != bindings_.size()) llvm::report_fatal_error("owner reader bindings changed during transformation");
    llvm::json::Array entries;
    for (unsigned index = 0; index != bindings_.size(); ++index) {
        const auto &before = bindings_[index], &after = current[index];
        if (before.capture != after.capture || before.cache != after.cache || before.table != after.table ||
                before.key != after.key || before.owner != after.owner || before.plan != after.plan || before.index != after.index ||
                !after.capture->hasFnAttribute("pyobf.cff.transformed") || !after.cache->hasFnAttribute("pyobf.cff.transformed"))
            llvm::report_fatal_error("owner reader lost its exact selected code/storage binding");
        const auto flow = check_owner_reader_flow(*after.capture, after.key, true, false); checked(flow);
        checked(check_owner_reader_flow(*after.cache, after.key, false, false));
        if (flow.volatile_reads != reads_[index]) llvm::report_fatal_error("owner reader volatile code reads were changed or coalesced");
        entries.push_back(llvm::json::Object{{"index", after.index}, {"owner", after.owner}, {"key", key_text(after.key)},
            {"plan_sha256", after.plan}, {"binding_symbol", after.symbol}, {"capture", after.capture->getName()},
            {"cache", after.cache->getName()}, {"volatile_reads", flow.volatile_reads}, {"binding_stride", 32},
            {"ir_binding_verified", true}, {"ir_mapped_bytes_to_sha_verified", true}, {"early_key_comparison_verified", true}});
    }
    return llvm::json::Object{{"schema_version", 1}, {"scheme", "source-owned-reader-v1"}, {"entries", std::move(entries)}};
}
}
