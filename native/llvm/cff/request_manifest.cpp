#include "request_manifest.hpp"

#include <optional>
#include <set>

#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff {

void write_request_manifest(const llvm::Module &module, llvm::StringRef path,
                            const Requests &requests) {
    llvm::json::Array functions;
    for (const auto &[name, request] : requests) {
        llvm::json::Object row;
        row["function"] = name;
        row["defined"] = request.defined;
        llvm::json::Array sites;
        for (const auto &site : request.sites) {
            llvm::json::Object item;
            item["id"] = site.id;
            item["component"] = site.component;
            sites.push_back(std::move(item));
        }
        row["sites"] = std::move(sites);
        if (!request.marker.empty()) {
            row["marker"] = request.marker;
        }
        functions.push_back(std::move(row));
    }
    llvm::json::Object root;
    root["module"] = module.getModuleIdentifier();
    root["functions"] = std::move(functions);
    std::error_code error;
    llvm::raw_fd_ostream output(path, error, llvm::sys::fs::OF_Text);
    if (error) {
        llvm::report_fatal_error(
            ("cannot write native CFF request manifest: " + error.message()).c_str());
    }
    output << llvm::json::Value(std::move(root)) << '\n';
    output.flush();
    if (output.has_error()) {
        llvm::report_fatal_error("failed to flush native CFF request manifest");
    }
}

Requests read_request_manifest(llvm::StringRef path) {
    const auto input = llvm::MemoryBuffer::getFile(path);
    if (!input) {
        llvm::report_fatal_error("cannot read native CFF request manifest");
    }
    auto parsed = llvm::json::parse(input.get()->getBuffer());
    if (!parsed) {
        llvm::consumeError(parsed.takeError());
        llvm::report_fatal_error("native CFF request manifest is not valid JSON");
    }
    const auto *root = parsed->getAsObject();
    const auto *functions = root == nullptr ? nullptr : root->getArray("functions");
    if (functions == nullptr) {
        llvm::report_fatal_error("native CFF request manifest needs a functions array");
    }
    Requests requests;
    for (const auto &item : *functions) {
        const auto *row = item.getAsObject();
        const auto name = row == nullptr ? std::nullopt : row->getString("function");
        const auto defined = row == nullptr ? std::nullopt : row->getBoolean("defined");
        if (!name || name->empty() || !defined) {
            llvm::report_fatal_error("native CFF request manifest has an invalid row");
        }
        const auto marker = row->getString("marker");
        Request request{marker ? marker->str() : std::string{}, *defined, {}};
        if (const auto *value = row->get("sites")) {
            const auto *sites = value->getAsArray();
            if (sites == nullptr) llvm::report_fatal_error("native CFF request sites must be an array");
            std::set<std::string> ids;
            for (const auto &entry : *sites) {
                const auto *site = entry.getAsObject();
                const auto id = site == nullptr ? std::nullopt : site->getString("id");
                const auto component = site == nullptr ? std::nullopt : site->getString("component");
                if (!id || id->empty() || !component || find_component(*component) == nullptr ||
                    !ids.insert(id->str()).second)
                    llvm::report_fatal_error("invalid or duplicate native CFF requested site");
                request.sites.push_back({id->str(), component->str()});
            }
        }
        const auto [it, inserted] = requests.emplace(name->str(), std::move(request));
        if (!inserted) {
            llvm::report_fatal_error("native CFF request manifest repeats a function");
        }
    }
    if (requests.empty()) {
        llvm::report_fatal_error("native CFF request manifest is empty");
    }
    return requests;
}

}  // namespace pyobfuscator::native::cff
