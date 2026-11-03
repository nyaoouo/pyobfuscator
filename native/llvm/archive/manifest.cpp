#include "plan.hpp"

#include "llvm/ADT/StringExtras.h"

namespace pyobfuscator::native::archive {

llvm::json::Object private_plan(const std::vector<PlannedRecord> &records) {
    llvm::json::Array rows;
    for (const auto &record : records) {
        llvm::json::Object row;
        row["id"] = record.id;
        row["kind"] = record.kind;
        row["bit_width"] = record.bit_width;
        row["alignment"] = record.alignment;
        row["byte_order"] = record.byte_order;
        row["data_hex"] = llvm::toHex(llvm::ArrayRef<std::uint8_t>(record.bytes));
        rows.push_back(std::move(row));
    }
    llvm::json::Object root;
    root["schema_version"] = 1;
    root["records"] = std::move(rows);
    return root;
}

}  // namespace pyobfuscator::native::archive
