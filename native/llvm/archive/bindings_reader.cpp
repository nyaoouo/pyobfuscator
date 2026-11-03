#include "bindings.hpp"
#include "metadata.hpp"

#include <set>

#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"

namespace pyobfuscator::native::archive {
namespace {

void fields(const llvm::json::Object &object, std::initializer_list<llvm::StringRef> allowed) {
    for (const auto &entry : object) {
        bool found = false;
        for (const auto name : allowed) found |= llvm::StringRef(entry.first) == name;
        if (!found) invalid_binding("unknown private binding field");
    }
}

std::string hex(const llvm::json::Object &object, llvm::StringRef name, unsigned bytes) {
    const auto value = object.getString(name);
    if (!value || value->size() != bytes * 2) invalid_binding("invalid private hex length");
    for (const auto byte : *value)
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f')))
            invalid_binding("private hex must be canonical lowercase");
    return value->str();
}

std::uint64_t integer(const llvm::json::Object &object, llvm::StringRef name, std::uint64_t maximum) {
    const auto value = object.getInteger(name);
    if (!value || *value < 0 || static_cast<std::uint64_t>(*value) > maximum)
        invalid_binding("invalid private integer field");
    return static_cast<std::uint64_t>(*value);
}

}  // namespace

Bindings read_bindings(const std::string &path) {
    const auto file = llvm::MemoryBuffer::getFile(path);
    if (!file || file.get()->getBufferSize() > 32 * 1024 * 1024) invalid_binding("cannot read bounded private bindings");
    auto parsed = llvm::json::parse(file.get()->getBuffer());
    if (!parsed) { llvm::consumeError(parsed.takeError()); invalid_binding("invalid private JSON"); }
    const auto *root = parsed->getAsObject();
    if (root == nullptr) invalid_binding("private bindings must be an object");
    fields(*root, {"schema_version", "plan_sha256", "package_sha256", "archive_id", "records"});
    if (root->getInteger("schema_version") != 1) invalid_binding("private binding schema must be 1");
    Bindings result;
    result.plan_hash = hex(*root, "plan_sha256", 32);
    result.package_hash = hex(*root, "package_sha256", 32);
    result.archive_id = hex(*root, "archive_id", 16);
    const auto *records = root->getArray("records");
    if (records == nullptr || records->size() > 65536) invalid_binding("invalid binding count");
    std::set<std::string> ids;
    for (const auto &value : *records) {
        const auto *record = value.getAsObject();
        if (record == nullptr) invalid_binding("private record must be an object");
        fields(*record, {"id", "index", "wrapper", "key_hex", "size", "alignment"});
        const auto id = record->getString("id"), wrapper = record->getString("wrapper");
        if (!id || id->empty() || id->size() > 128 || !ids.insert(id->str()).second || !wrapper)
            invalid_binding("invalid or duplicate record identity");
        RecordBinding binding;
        binding.id = id->str();
        binding.index = static_cast<unsigned>(integer(*record, "index", 65535));
        if (binding.index != result.records.size()) invalid_binding("binding indices must be contiguous");
        binding.wrapper = wrapper->str();
        if (binding.wrapper != "__pyobf_archive_" + result.archive_id + "_" + std::to_string(binding.index))
            invalid_binding("wrapper identity disagrees with archive/index");
        binding.size = integer(*record, "size", 16 * 1024 * 1024);
        binding.alignment = static_cast<unsigned>(integer(*record, "alignment", 4096));
        if (binding.alignment == 0 || (binding.alignment & (binding.alignment - 1))) invalid_binding("invalid record alignment");
        const auto key = hex(*record, "key_hex", 32);
        const auto digit = [](char value) { return value <= '9' ? value - '0' : value - 'a' + 10; };
        for (unsigned index = 0; index < 32; ++index)
            binding.key[index] = static_cast<std::uint8_t>((digit(key[index * 2]) << 4) | digit(key[index * 2 + 1]));
        result.records.push_back(std::move(binding));
    }
    return result;
}

}  // namespace pyobfuscator::native::archive
