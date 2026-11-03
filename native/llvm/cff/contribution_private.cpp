#include "contribution_private.hpp"

#include <set>
#include <optional>
#include <string>
#include <vector>

#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/ADT/StringExtras.h"

namespace pyobfuscator::native::cff {
namespace {
[[noreturn]] void invalid(const char *reason) {
    llvm::report_fatal_error(llvm::Twine("native contribution input: ") + reason);
}
std::uint32_t word(const llvm::json::Value *value, bool nonzero = false) {
    const auto number = value == nullptr ? std::optional<std::int64_t>{} : value->getAsInteger();
    if (!number || *number < (nonzero ? 1 : 0) || *number > UINT32_MAX) invalid("expected a bounded uint32");
    return static_cast<std::uint32_t>(*number);
}

// LLVM's JSON object keeps the last occurrence of a key. Check the raw,
// already-validated input so a repeated private rule cannot be hidden there.
class UniqueObjectKeys {
public:
    explicit UniqueObjectKeys(llvm::StringRef input) : input_(input) {}

    bool check() {
        if (!value()) return false;
        space();
        return position_ == input_.size();
    }

    bool duplicate() const { return duplicate_; }

private:
    void space() {
        while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\r' || input_[position_] == '\n')) ++position_;
    }

    llvm::StringRef string_token() {
        if (position_ == input_.size() || input_[position_] != '"') return {};
        const auto start = position_++;
        while (position_ < input_.size()) {
            const auto character = input_[position_++];
            if (character == '\\') {
                if (position_ == input_.size()) return {};
                ++position_;
            } else if (character == '"') return input_.slice(start, position_);
        }
        return {};
    }

    bool object() {
        ++position_;
        space();
        if (position_ < input_.size() && input_[position_] == '}') { ++position_; return true; }
        std::set<std::string> keys;
        while (position_ < input_.size()) {
            const auto token = string_token();
            if (token.empty()) return false;
            auto parsed = llvm::json::parse(token);
            if (!parsed) { llvm::consumeError(parsed.takeError()); return false; }
            const auto key = parsed->getAsString();
            if (!key) return false;
            if (!keys.insert(key->str()).second) { duplicate_ = true; return false; }
            space();
            if (position_ == input_.size() || input_[position_++] != ':') return false;
            if (!value()) return false;
            space();
            if (position_ == input_.size()) return false;
            const auto separator = input_[position_++];
            if (separator == '}') return true;
            if (separator != ',') return false;
            space();
        }
        return false;
    }

    bool array() {
        ++position_;
        space();
        if (position_ < input_.size() && input_[position_] == ']') { ++position_; return true; }
        while (value()) {
            space();
            if (position_ == input_.size()) return false;
            const auto separator = input_[position_++];
            if (separator == ']') return true;
            if (separator != ',') return false;
        }
        return false;
    }

    bool value() {
        space();
        if (position_ == input_.size()) return false;
        if (input_[position_] == '{') return object();
        if (input_[position_] == '[') return array();
        if (input_[position_] == '"') return !string_token().empty();
        const auto start = position_;
        while (position_ < input_.size() && input_[position_] != ',' &&
                input_[position_] != '}' && input_[position_] != ']' &&
                input_[position_] != ' ' && input_[position_] != '\t' &&
                input_[position_] != '\r' && input_[position_] != '\n') ++position_;
        return position_ != start;
    }

    llvm::StringRef input_;
    std::size_t position_ = 0;
    bool duplicate_ = false;
};
}
std::shared_ptr<const ContributionPrivate> read_contribution_private(llvm::StringRef path,
    bool allow_bounded_schema4_sites) {
    if (path.empty()) return {};
    const auto file = llvm::MemoryBuffer::getFile(path);
    if (!file) invalid("cannot read file");
    auto parsed = llvm::json::parse(file.get()->getBuffer());
    if (!parsed) { llvm::consumeError(parsed.takeError()); invalid("invalid JSON"); }
    UniqueObjectKeys unique(file.get()->getBuffer());
    if (!unique.check()) invalid(unique.duplicate() ? "duplicate JSON object key" : "invalid JSON tokenization");
    const auto *root = parsed->getAsObject();
    if (root == nullptr || (root->getInteger("schema_version") != 1 && root->getInteger("schema_version") != 2 &&
            root->getInteger("schema_version") != 3 && root->getInteger("schema_version") != 4) ||
            (root->getInteger("schema_version") == 4 ? root->getString("provider") != "source-mixed-v1" :
            root->getInteger("schema_version") == 3 ? root->getString("provider") != "site-mixed-v1" :
            (root->getString("provider") != "owned-context-v1" && root->getString("provider") != "measured-scope-v1")))
        invalid("unsupported schema/provider");
    const auto schema = *root->getInteger("schema_version");
    std::set<std::string> fields{"schema_version", "provider", "routing_tag", "domain", "private_words", "owners"};
    if (schema == 1) fields.insert("source"); else { fields.insert("sources"); fields.insert("bindings"); }
    if (schema == 4) { fields.insert("root_scheme"); fields.insert("measured_private_words"); }
    for (const auto &entry : *root) if (!fields.count(entry.first.str())) invalid("unknown field");
    auto result = std::make_shared<ContributionPrivate>();
    const auto bytes = file.get()->getBuffer();
    result->input_sha256 = llvm::toHex(llvm::SHA256::hash(llvm::ArrayRef<std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size())), true);
    result->schema = schema;
    result->provider = root->getString("provider")->str();
    result->routing = word(root->get("routing_tag"), true);
    result->domain = word(root->get("domain"), true);
    result->source = schema == 1 ? word(root->get("source"), true) : 0;
    const auto *words = root->getArray("private_words");
    if (words == nullptr || words->size() != 8) invalid("expected eight private words");
    for (unsigned index = 0; index != 8; ++index) result->words[index] = word(&(*words)[index]);
    if (schema == 4 && (root->get("root_scheme") || root->get("measured_private_words"))) {
        if (root->getString("root_scheme") != "provider-split-v1")
            invalid("provider-split root scheme is missing or unsupported");
        const auto *measured = root->getArray("measured_private_words");
        if (measured == nullptr || measured->size() != 8)
            invalid("provider-split needs eight measured private words");
        for (unsigned index = 0; index != 8; ++index)
            result->measured_words[index] = word(&(*measured)[index]);
        if (result->measured_words == result->words)
            invalid("provider-split roots must be distinct");
        result->provider_split = true;
    }
    const auto *owners = root->getObject("owners");
    if (owners == nullptr || owners->empty() || owners->size() > 65536) invalid("invalid owner inventory");
    std::set<std::uint32_t> identities;
    for (const auto &entry : *owners) {
        const auto id = word(&entry.second, true);
        if (llvm::StringRef(entry.first).empty() || !identities.insert(id).second) invalid("empty owner or colliding function identity");
        result->owners.emplace(entry.first.str(), id);
    }
    if (schema >= 2) read_contribution_sources(*root, *result, allow_bounded_schema4_sites);
    return result;
}
std::uint32_t reference_contribution(const ContributionPrivate &input, llvm::StringRef owner,
    std::uint32_t site, std::uint32_t current, std::uint32_t source, llvm::StringRef provider) {
    const auto found = input.owners.find(owner.str());
    if (found == input.owners.end()) invalid("required owner has no private reference");
    constexpr char domain[] = "pyobf.native.contribution.context.v1";
    std::vector<std::uint8_t> material(domain, domain + sizeof(domain));
    const auto append = [&](std::uint32_t value) {
        for (unsigned byte = 0; byte != 4; ++byte) material.push_back(static_cast<std::uint8_t>(value >> (byte * 8)));
    };
    for (auto value : {input.routing, input.domain, found->second, site, source == 0 ? input.source : source, current}) append(value);
    if (input.provider_split && provider != "owned-context-v1" && provider != "measured-scope-v1")
        invalid("provider-split reference has no exact source provider");
    const auto &words = input.provider_split && provider == "measured-scope-v1" ? input.measured_words : input.words;
    for (auto value : words) append(value);
    const auto digest = llvm::SHA256::hash(material);
    std::uint32_t value = 0;
    for (unsigned byte = 0; byte != 4; ++byte) value |= std::uint32_t(digest[byte]) << (byte * 8);
    return value == 0 ? 1 : value;
}
}
