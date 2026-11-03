#include "reference_routes.hpp"
#include "site_report.hpp"
#include "site_provenance.hpp"

#include <algorithm>
#include <map>
#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

unsigned normalize_reference_component(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage,
                                         bool imported) {
    const auto component = imported ? "import-routes" : "reference-routes";
    const auto sites = discover_function_references(function, recipe, imported);
    std::vector<const llvm::Function *> targets;
    for (const auto &site : sites) if (site.reason.empty()) {
        const auto *target = reference_function(site.instruction->getOperand(site.operand));
        if (std::find(targets.begin(), targets.end(), target) == targets.end()) targets.push_back(target);
    }
    if (targets.empty()) return 0;
    std::vector<const llvm::Function *> extras;
    for (const auto &candidate : *function.getParent())
        if (!imported && !candidate.isDeclaration() && !candidate.isIntrinsic() && !candidate.hasAvailableExternallyLinkage() &&
            candidate.getAddressSpace() == 0 &&
            std::find(targets.begin(), targets.end(), &candidate) == targets.end()) extras.push_back(&candidate);
    const auto name_less = [](const auto *left, const auto *right) { return left->getName() < right->getName(); };
    std::sort(targets.begin(), targets.end(), name_less);
    std::sort(extras.begin(), extras.end(), name_less);
    const auto limit = imported ? recipe.max_import_slots : recipe.max_reference_slots;
    const auto extra_count = std::min<std::size_t>({3, extras.size(), limit - targets.size() - 1});
    targets.insert(targets.end(), extras.begin(), extras.begin() + extra_count);
    unsigned slots = 2;
    while (slots <= targets.size()) slots *= 2;
    targets.resize(slots, nullptr);
    std::uint64_t random = recipe.seeds.at(component);
    for (unsigned index = slots - 1; index > 0; --index) {
        random = random * 6364136223846793005ull + 1442695040888963407ull;
        std::swap(targets[index], targets[(random >> 32) % (index + 1)]);
    }
    auto &entry = function.getEntryBlock();
    llvm::IRBuilder<> allocation(&*entry.getFirstInsertionPt());
    auto *array = llvm::ArrayType::get(allocation.getPtrTy(), slots);
    auto *table = allocation.CreateAlloca(array, nullptr, imported ? "pyobf.import.table" : "pyobf.reference.table");
    const auto alignment = function.getParent()->getDataLayout().getABITypeAlign(allocation.getPtrTy());
    table->setAlignment(alignment);
    std::vector<llvm::Metadata *> profile{llvm::ConstantAsMetadata::get(allocation.getInt32(slots))};
    if (imported) profile.push_back(llvm::MDString::get(function.getContext(), "import-routes"));
    table->setMetadata("pyobf.ref.table", llvm::MDNode::get(function.getContext(), profile));
    llvm::Instruction *insertion = entry.getTerminator();
    for (auto &instruction : entry)
        if (!llvm::isa<llvm::AllocaInst>(instruction) && !llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) {
            insertion = &instruction; break;
        }
    llvm::IRBuilder<> initializer(insertion);
    std::map<const llvm::Function *, unsigned> indices;
    std::vector<llvm::Metadata *> planned;
    for (unsigned index = 0; index < slots; ++index) {
        llvm::Value *target = targets[index] == nullptr ? static_cast<llvm::Value *>(llvm::ConstantPointerNull::get(initializer.getPtrTy())) :
            const_cast<llvm::Function *>(targets[index]);
        if (imported) planned.push_back(llvm::ValueAsMetadata::get(target));
        else {
            auto *address = llvm::cast<llvm::Instruction>(initializer.CreateInBoundsGEP(array, table,
                {initializer.getInt32(0), initializer.getInt32(index)}, "pyobf.reference.init"));
            auto *store = initializer.CreateStore(target, address, true);
            store->setAlignment(alignment);
            for (auto *instruction : {address, static_cast<llvm::Instruction *>(store)})
                instruction->setMetadata("pyobf.ref.initializer", llvm::MDNode::get(function.getContext(), {}));
        }
        if (targets[index] != nullptr) indices.emplace(targets[index], index);
    }
    if (imported) table->setMetadata("pyobf.ref.layout", llvm::MDNode::get(function.getContext(), planned));
    unsigned routed = 0;
    for (const auto &site : sites) {
        if (!site.reason.empty()) continue;
        auto *instruction = site.instruction;
        auto *target = const_cast<llvm::Function *>(reference_function(instruction->getOperand(site.operand)));
        auto *before = instruction;
        if (const auto *phi = llvm::dyn_cast<llvm::PHINode>(instruction))
            before = phi->getIncomingBlock(site.operand)->getTerminator();
        llvm::IRBuilder<> builder(before);
        builder.SetCurrentDebugLocation(instruction->getDebugLoc());
        llvm::Value *address = imported ? static_cast<llvm::Value *>(table) :
            builder.CreateInBoundsGEP(array, table, {builder.getInt32(0), builder.getInt32(indices.at(target))}, "pyobf.reference.address");
        const auto salt = component_seed(recipe.seeds.at(component), function.getName(),
            instruction_site_id(*instruction, component, site.operand));
        const auto *call = llvm::dyn_cast<llvm::CallBase>(instruction);
        const bool callee = call != nullptr && call->isCallee(&instruction->getOperandUse(site.operand));
        std::vector<llvm::Metadata *> pending{
            llvm::ValueAsMetadata::get(target), llvm::ConstantAsMetadata::get(builder.getInt32(indices.at(target))),
            llvm::ConstantAsMetadata::get(builder.getInt32(salt)),
            llvm::MDString::get(function.getContext(), callee ? "call-target" : "function-address")};
        if (imported) pending.push_back(llvm::MDString::get(function.getContext(), "import-routes"));
        auto *load = builder.CreateLoad(builder.getPtrTy(), address, "pyobf.reference.target");
        load->setVolatile(true);
        load->setAlignment(alignment);
        (imported ? static_cast<llvm::Instruction *>(load) : llvm::cast<llvm::Instruction>(address))->setMetadata(
            "pyobf.ref.pending", llvm::MDNode::get(function.getContext(), pending));
        coverage.relocate_use(component, *instruction, site.operand, *load, 0);
        instruction->setOperand(site.operand, load);
        ++routed;
    }
    coverage.preparation_metric(component, "source_uses", routed);
    coverage.preparation_metric(component, "table_slots", slots);
    coverage.preparation_metric(component, "per_invocation_bytes",
        static_cast<unsigned>(function.getParent()->getDataLayout().getTypeAllocSize(array).getFixedValue()));
    if (routed) {
        function.removeFnAttr(llvm::Attribute::Memory);
        function.removeFnAttr(llvm::Attribute::Speculatable);
    }
    return routed;
}

unsigned normalize_reference_routes(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    return normalize_reference_component(function, recipe, coverage, false);
}

void hoist_reference_storage(llvm::Function &function) {
    std::vector<llvm::AllocaInst *> tables;
    for (auto &block : function) for (auto &instruction : block)
        if (instruction.getMetadata("pyobf.ref.table") != nullptr)
            tables.push_back(llvm::cast<llvm::AllocaInst>(&instruction));
    for (auto *table : tables)
        if (table->getParent() != &function.getEntryBlock())
            table->moveBefore(function.getEntryBlock().getFirstInsertionPt());
}

unsigned prepare_reference_routes(llvm::Function &function, llvm::Value *, const ResolvedRecipe &, SiteCoverage &) {
    std::vector<llvm::Instruction *> initializers;
    for (auto &block : function) for (auto &instruction : block)
        if (instruction.getMetadata("pyobf.ref.initializer") != nullptr) initializers.push_back(&instruction);
    for (auto *instruction : initializers) instruction->moveBefore(function.getEntryBlock().getTerminator()->getIterator());
    return static_cast<unsigned>(initializers.size());
}

}  // namespace pyobfuscator::native::cff
