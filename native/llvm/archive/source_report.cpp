#include "source_report.hpp"
#include "empty_plan.hpp"
#include "key_address.hpp"
#include "metadata.hpp"
#include "../cff/cff.hpp"
#include "../cff/site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <array>
#include <map>
#include <set>

namespace pyobfuscator::native::archive {
namespace {

struct Group {
    const llvm::MDNode *source = nullptr;
    const llvm::CallInst *gate = nullptr;
    std::array<const llvm::StoreInst *, 8> keys{}, clears{};
    bool duplicate = false;
};

bool valid(const Group &group, bool bound) {
    const auto *gate = group.gate;
    const auto *callee = gate == nullptr ? nullptr : routed_callee(*gate);
    const auto *frame = gate == nullptr || gate->arg_size() != 3 ? nullptr :
        llvm::dyn_cast<llvm::AllocaInst>(gate->getArgOperand(0));
    if (group.duplicate || group.source == nullptr || callee == nullptr || callee->isDeclaration() ||
        !callee->hasFnAttribute("pyobf.archive.wrapper") || frame == nullptr ||
        callee->getFnAttribute("pyobf.archive.wrapper").getValueAsString() != text_field(group.source, 1) ||
        frame->getAllocatedType() != llvm::ArrayType::get(llvm::Type::getInt32Ty(frame->getContext()), 8) ||
        gate->getMetadata("pyobf.archive.materialized") == nullptr) return false;
    const auto *capacity = llvm::dyn_cast<llvm::ConstantInt>(gate->getArgOperand(2));
    if (gate->getArgOperand(1) != value_field(group.source, 8) || capacity == nullptr ||
        capacity->getZExtValue() != number_field(group.source, 9)) return false;
    for (unsigned lane = 0; lane < 8; ++lane) {
        const auto *key = group.keys[lane], *clear = group.clears[lane];
        const auto *zero = clear == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(clear->getValueOperand());
        if (key == nullptr || clear == nullptr || !key->isVolatile() || !clear->isVolatile() ||
            !key->getValueOperand()->getType()->isIntegerTy(32) || zero == nullptr || !zero->isZero() ||
            !is_key_address(key->getPointerOperand(), frame, lane) || !is_key_address(clear->getPointerOperand(), frame, lane))
            return false;
        if (bound) {
            if (key->getMetadata("pyobf.archive.key-bound") == nullptr ||
                key->getMetadata("pyobf.archive.key-material") != nullptr || llvm::isa<llvm::Constant>(key->getValueOperand())) return false;
        } else if (key->getMetadata("pyobf.archive.key-material") == nullptr ||
                   key->getMetadata("pyobf.archive.key-bound") != nullptr ||
                   key->getParent() != gate->getParent() || clear->getParent() != gate->getParent() ||
                   !key->comesBefore(gate) || !gate->comesBefore(clear)) return false;
    }
    return true;
}

}  // namespace

SourceReport inspect_sources(llvm::Function &function, const std::vector<cff::RequestedSite> &requests,
                                bool bound, bool strict_requests) {
    SourceReport result;
    std::map<std::string, Group> groups;
    std::map<std::string, bool> source_ok;
    if (const auto *sources = function.getParent()->getNamedMetadata("pyobf.archive.sources"))
        for (const auto *row : sources->operands()) {
            if (value_field(row, 0) != &function) continue;
            const auto source = text_field(row, 2), id = text_field(row, 1) + ":" + source;
            if (row->getNumOperands() != 10 || !groups.emplace(id, Group{row}).second)
                invalid_binding("duplicate or malformed source acquisition inventory");
            source_ok.emplace(source, true);
        }
    for (const auto &block : function) for (const auto &instruction : block) {
        for (const auto name : {"pyobf.archive.key-slot", "pyobf.archive.key-clear", "pyobf.archive.gate"}) {
            const auto *tag = instruction.getMetadata(name);
            if (tag == nullptr) continue;
            const auto found = groups.find(acquisition_id(tag));
            if (found == groups.end()) { result.failure = "archive instruction is absent from source inventory"; continue; }
            auto &group = found->second;
            if (llvm::StringRef(name) == "pyobf.archive.gate") {
                if (group.gate != nullptr) group.duplicate = true;
                group.gate = llvm::dyn_cast<llvm::CallInst>(&instruction);
            } else {
                const auto lane = number_field(tag, 2);
                if (lane >= 8) { group.duplicate = true; continue; }
                auto &target = llvm::StringRef(name) == "pyobf.archive.key-slot" ? group.keys[lane] : group.clears[lane];
                if (target != nullptr) group.duplicate = true;
                target = llvm::dyn_cast<llvm::StoreInst>(&instruction);
            }
        }
    }
    unsigned valid_groups = 0;
    llvm::json::Array helpers;
    for (const auto &[id, group] : groups) {
        const bool complete = valid(group, bound);
        valid_groups += complete;
        if (complete) helpers.push_back(llvm::json::Object{{"function", routed_callee(*group.gate)->getName()},
            {"acquisition", id}, {"source_id", text_field(group.source, 2)}});
        source_ok[text_field(group.source, 2)] &= complete;
        llvm::json::Object private_row;
        private_row["acquisition"] = id;
        private_row["source_id"] = text_field(group.source, 2);
        private_row["original_block"] = text_field(group.source, 3);
        private_row["instruction_index"] = number_field(group.source, 4);
        private_row["operand_index"] = number_field(group.source, 5);
        private_row["source"] = text_field(group.source, 6);
        private_row["line"] = number_field(group.source, 7);
        private_row["complete"] = complete;
        llvm::json::Array children;
        for (unsigned lane = 0; lane < 8; ++lane) if (group.keys[lane] != nullptr) {
            llvm::json::Object child;
            child["role"] = "key-word32";
            child["lane"] = lane;
            child["site_id"] = cff::instruction_site_id(*group.keys[lane], "constant-archive", 0);
            children.push_back(std::move(child));
        }
        if (group.gate != nullptr) {
            llvm::json::Object child;
            child["role"] = "acquisition";
            child["site_id"] = cff::instruction_site_id(*group.gate, "constant-archive", 0);
            children.push_back(std::move(child));
        }
        private_row["children"] = std::move(children);
        result.private_map.push_back(std::move(private_row));
    }
    if (valid_groups != groups.size()) result.failure = "archive source has incomplete key/frame/clear/gate binding";
    std::set<std::string> wanted;
    for (const auto &request : requests) if (request.component == "constant-archive") wanted.insert(request.id);
    const bool preoptimization = !wanted.empty();
    for (const auto &[source, complete] : source_ok) wanted.insert(source);
    llvm::json::Array rows;
    unsigned applied = 0;
    for (const auto &id : wanted) {
        const auto found = source_ok.find(id);
        const bool complete = found != source_ok.end() && found->second;
        llvm::json::Object row;
        row["id"] = id;
        row["status"] = complete ? (bound ? "applied" : "eligible") :
            found == source_ok.end() ? "optimized-away" : "unsupported";
        applied += bound && complete;
        rows.push_back(std::move(row));
        if (!complete && strict_requests) result.failure = "required archive source request is absent or incomplete";
    }
    result.report["request_scope"] = preoptimization ? "pre-optimization-source" : "planned-source";
    result.report["requested"] = static_cast<std::uint64_t>(wanted.size());
    result.report["applied"] = applied;
    result.report["acquisitions"] = static_cast<std::uint64_t>(groups.size());
    result.report["complete_acquisitions"] = valid_groups;
    result.report["helpers"] = std::move(helpers);
    result.report["sources"] = std::move(rows);
    return result;
}

void preflight_prepared(llvm::Module &module, const std::map<std::string, cff::ResolvedRecipe> &recipes) {
    if (module.getNamedMetadata("pyobf.archive.empty") != nullptr) {
        verify_empty_prepared(module);
        return;
    }
    if (module.getNamedMetadata("pyobf.archive.prepared") == nullptr) return;
    const auto *sources = module.getNamedMetadata("pyobf.archive.sources");
    if (sources == nullptr || sources->getNumOperands() == 0) invalid_binding("prepared archive has no source inventory");
    std::set<const llvm::Function *> owners;
    for (const auto *row : sources->operands()) {
        const auto *function = llvm::dyn_cast<llvm::Function>(value_field(row, 0));
        const auto recipe = function == nullptr ? recipes.end() : recipes.find(function->getName().str());
        if (recipe == recipes.end() || !recipe->second.enabled("constant-archive") ||
            !function->hasFnAttribute("pyobf.archive.planned"))
            invalid_binding("prepared archive owner must be selected with constant-archive enabled");
        owners.insert(function);
    }
    for (const auto &function : module)
        if (function.hasFnAttribute("pyobf.archive.planned") && !owners.count(&function))
            invalid_binding("planned function is absent from source inventory");
    for (const auto &[name, label] : cff::collect_marked_functions(module))
        if (label == "pyobf.native.sdk" && !recipes.count(name))
            invalid_binding("materialized archive requires selected SDK support definitions");
}

void finish_bindings(llvm::Module &module) {
    if (module.getNamedMetadata("pyobf.archive.prepared") == nullptr) return;
    if (module.getNamedMetadata("pyobf.archive.empty") != nullptr) verify_empty_prepared(module);
    for (auto &function : module) {
        if (function.hasFnAttribute("pyobf.archive.planned")) {
            const auto sources = inspect_sources(function, {}, true);
            if (!sources.failure.empty()) invalid_binding("final source binding is incomplete");
            function.removeFnAttr("pyobf.archive.planned");
        }
        for (auto &block : function) for (auto &instruction : block) {
            if (instruction.getMetadata("pyobf.archive.key-material") != nullptr)
                invalid_binding("raw key material survived final CFF");
            for (const auto name : {"pyobf.archive.key-slot", "pyobf.archive.key-clear", "pyobf.archive.key-bound",
                                  "pyobf.archive.gate", "pyobf.archive.materialized"}) instruction.setMetadata(name, nullptr);
        }
    }
    module.eraseNamedMetadata(module.getNamedMetadata("pyobf.archive.prepared"));
    module.eraseNamedMetadata(module.getNamedMetadata("pyobf.archive.sources"));
    if (auto *empty = module.getNamedMetadata("pyobf.archive.empty")) module.eraseNamedMetadata(empty);
}

}  // namespace pyobfuscator::native::archive
