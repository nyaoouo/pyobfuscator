#include "generated_ownership.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
llvm::json::Object generated_ownership(const llvm::Module &module,
    const std::map<std::string, GeneratedDefinition> &generated, const llvm::json::Array &functions) {
    llvm::json::Array edges;
    const auto add = [&](llvm::StringRef owner, llvm::StringRef helper, llvm::StringRef component,
                         llvm::StringRef site) {
        const auto *source = module.getFunction(owner), *target = module.getFunction(helper);
        if (source == nullptr || source->isDeclaration() || target == nullptr || target->isDeclaration() ||
                owner == helper || site.empty())
            llvm::report_fatal_error("native generated ownership lost an actual definition or source site");
        edges.push_back(llvm::json::Object{{"owner", owner}, {"helper", helper},
            {"component", component}, {"site", site}});
    };
    for (const auto &[name, definition] : generated)
        add(definition.owner, name, definition.component, definition.site);
    for (const auto &value : functions) {
        const auto *row = value.getAsObject();
        if (row == nullptr) llvm::report_fatal_error("native generated ownership has an invalid function row");
        const auto *archive = row->getObject("archive_sources");
        if (archive == nullptr) continue;
        const auto *helpers = archive->getArray("helpers");
        if (helpers == nullptr) llvm::report_fatal_error("native archive ownership lacks acquisition helpers");
        const auto owner = row->getString("function");
        if (!owner) llvm::report_fatal_error("native archive ownership lacks its source definition");
        for (const auto &entry : *helpers) {
            const auto *helper = entry.getAsObject();
            if (helper == nullptr || !helper->getString("function") || !helper->getString("acquisition"))
                llvm::report_fatal_error("native archive ownership has an invalid acquisition");
            add(*owner, *helper->getString("function"), "constant-archive", *helper->getString("acquisition"));
        }
    }
    return llvm::json::Object{{"schema_version", 1}, {"verified", true}, {"edges", std::move(edges)}};
}
}
