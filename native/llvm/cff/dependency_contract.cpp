#include "recipe.hpp"

#include <functional>
#include <map>
#include <set>
#include <vector>

#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {

[[noreturn]] void invalid(const std::string &message) {
    llvm::report_fatal_error(llvm::StringRef("native CFF dependency contract: " + message));
}

struct Node {
    std::string id;
    std::vector<std::string> dependencies;
    int ready = 0;
    int first_use = 0;
};

std::string text(const llvm::json::Object &row, llvm::StringRef field) {
    const auto value = row.getString(field);
    if (!value || value->empty()) invalid("missing nonempty '" + field.str() + "'");
    return value->str();
}

int stage(const llvm::json::Object &row, llvm::StringRef field) {
    const auto value = text(row, field);
    if (value.size() != 2 || value[0] != 'L' || value[1] < '0' || value[1] > '5')
        invalid("runtime stage must be L0 through L5");
    return value[1] - '0';
}

std::map<std::string, Node> read_nodes(const llvm::json::Object &root,
                                      llvm::StringRef field, bool runtime) {
    std::map<std::string, Node> nodes;
    const auto *value = root.get(field);
    if (value == nullptr) return nodes;
    const auto *array = value->getAsArray();
    if (array == nullptr || array->empty()) invalid(field.str() + " must be a nonempty array");
    for (const auto &entry : *array) {
        const auto *row = entry.getAsObject();
        if (row == nullptr) invalid("node must be an object");
        for (const auto &item : *row) {
            if (item.first != "id" && item.first != "requires" &&
                !(runtime && (item.first == "ready_at" || item.first == "first_use" ||
                              item.first == "application_domain" ||
                              item.first == "protects_first_release")))
                invalid("unknown node field '" + item.first.str() + "'");
        }
        Node node;
        node.id = text(*row, "id");
        if (const auto *requirements = row->get("requires")) {
            const auto *dependencies = requirements->getAsArray();
            if (dependencies == nullptr) invalid("requires must be an array");
            std::set<std::string> unique;
            for (const auto &dependency : *dependencies) {
                const auto name = dependency.getAsString();
                if (!name || name->empty() || !unique.insert(name->str()).second)
                    invalid("requires has an invalid or duplicate dependency");
                node.dependencies.push_back(name->str());
            }
        }
        if (runtime) {
            node.ready = stage(*row, "ready_at");
            node.first_use = stage(*row, "first_use");
            if (node.ready > node.first_use) invalid("service used before readiness: " + node.id);
            for (const auto field_name : {"application_domain", "protects_first_release"}) {
                if (row->get(field_name) && !row->getBoolean(field_name).has_value())
                    invalid(std::string(field_name) + " must be Boolean");
            }
            const bool application = row->getBoolean("application_domain").value_or(false);
            const bool first_release = row->getBoolean("protects_first_release").value_or(false);
            if (first_release && (node.ready > 2 || application))
                invalid("first-release protector depends on application release: " + node.id);
        }
        if (!nodes.emplace(node.id, std::move(node)).second) invalid("duplicate node id");
    }
    return nodes;
}

llvm::json::Array order(const std::map<std::string, Node> &nodes, bool runtime) {
    llvm::json::Array result;
    std::map<std::string, int> marks;
    std::function<void(const std::string &)> visit = [&](const std::string &id) {
        const auto found = nodes.find(id);
        if (found == nodes.end()) invalid("unknown dependency: " + id);
        if (marks[id] == 1) invalid("dependency cycle at " + id);
        if (marks[id] == 2) return;
        marks[id] = 1;
        for (const auto &dependency : found->second.dependencies) {
            visit(dependency);
            if (runtime && nodes.at(dependency).ready > found->second.ready)
                invalid("service dependency unavailable at initialization: " + id);
        }
        marks[id] = 2;
        result.push_back(id);
    };
    for (const auto &[id, node] : nodes) visit(id);
    return result;
}

}  // namespace

llvm::json::Object validate_dependency_contract(const llvm::json::Object &root,
                                                llvm::StringRef domain) {
    const auto domains = read_nodes(root, "build_domains", false);
    const auto services = read_nodes(root, "runtime_services", true);
    if (!domains.empty() && !domains.count(domain.str())) invalid("current domain is undeclared");
    llvm::json::Object output;
    output["validation_scope"] = "declared-contracts-only";
    output["runtime_readiness_proven"] = false;
    output["build_domain_order"] = order(domains, false);
    output["runtime_service_order"] = order(services, true);
    output["domain_finalization_order"] = llvm::json::Array{
        "instrument-and-link", "freeze-code", "hash-and-fill-reserved-data",
        "verify-exact-domain", "pack", "parent-consumption"};
    output["state_binding_boundary"] = "all-structural-generation-before-state-assignment";
    for (const auto &component : registered_components()) {
        if (component.discover == nullptr ||
            (component.route != nullptr && component.stage != MutationStage::route) ||
            ((component.bind != nullptr || component.transition != nullptr) &&
             component.stage != MutationStage::bind && component.prepare == nullptr) ||
            (component.normalize != nullptr && component.stage != MutationStage::structure) ||
            (component.prepare != nullptr && component.stage != MutationStage::structure) ||
            (component.module_prepare != nullptr && component.stage != MutationStage::structure))
            invalid("invalid hook stage for " + std::string(component.name));
        if (component.stage > MutationStage::bind ||
            (component.stage == MutationStage::bind && component.changes_cfg &&
             llvm::StringRef(component.name) != "cfg"))
            invalid("unregistered late CFG mutation by " + std::string(component.name));
    }
    return output;
}

}  // namespace pyobfuscator::native::cff
