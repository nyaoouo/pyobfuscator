#include "indexed_locals.hpp"
#include "site_report.hpp"
#include "site_provenance.hpp"
#include "call_frames.hpp"

#include <algorithm>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

unsigned normalize_indexed_locals(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    const auto discovered = collect_local_objects(function, recipe);
    std::vector<LocalObject> objects;
    for (const auto &object : discovered) if (object.reason.empty()) objects.push_back(object);
    if (objects.empty()) return 0;
    unsigned slots = 2;
    while (slots <= objects.size()) slots *= 2;
    std::vector<llvm::AllocaInst *> entries(slots, nullptr);
    for (unsigned index = 0; index < objects.size(); ++index) entries[index] = objects[index].storage;
    std::uint64_t random = recipe.seeds.at("indexed-locals");
    for (unsigned index = slots - 1; index > 0; --index) {
        random = random * 6364136223846793005ull + 1442695040888963407ull;
        std::swap(entries[index], entries[(random >> 32) % (index + 1)]);
    }
    auto &entry = function.getEntryBlock();
    llvm::IRBuilder<> allocation(&*entry.getFirstInsertionPt());
    auto *array = llvm::ArrayType::get(allocation.getPtrTy(), slots);
    auto *table = allocation.CreateAlloca(array, nullptr, "pyobf.local.table");
    const auto alignment = function.getParent()->getDataLayout().getABITypeAlign(allocation.getPtrTy());
    table->setAlignment(alignment);
    table->setMetadata("pyobf.local.table", llvm::MDNode::get(function.getContext(),
        llvm::ConstantAsMetadata::get(allocation.getInt32(slots))));
    std::map<llvm::AllocaInst *, unsigned> indices;
    for (unsigned index = 0; index < slots; ++index) if (entries[index] != nullptr) indices[entries[index]] = index;
    unsigned routes = 0, controls = 0;
    std::vector<llvm::Metadata *> inventory;
    for (const auto &object : objects) {
        auto *descriptor = local_descriptor(*object.storage, indices.at(object.storage), object.uses.size(), object.control_uses);
        object.storage->setMetadata("pyobf.local.object", descriptor);
        inventory.push_back(descriptor);
        unsigned route = 0;
        for (const auto &use : object.uses) {
            auto *insertion = use.instruction;
            if (auto *phi = llvm::dyn_cast<llvm::PHINode>(insertion)) insertion = phi->getIncomingBlock(use.operand)->getTerminator();
            llvm::IRBuilder<> builder(insertion);
            const auto salt = component_seed(recipe.seeds.at("indexed-locals"), function.getName(),
                instruction_site_id(*use.instruction, "indexed-locals", use.operand) + "." + std::to_string(routes));
            // The private pending form is valid IR, but not executable output. Delay
            // the indexed GEP until binding so structural splitting cannot spill it.
            auto *load = builder.CreateLoad(builder.getPtrTy(), table, "pyobf.local.address");
            load->setVolatile(true);
            load->setAlignment(alignment);
            load->setMetadata("pyobf.local.pending", llvm::MDNode::get(function.getContext(), {
                descriptor, llvm::ConstantAsMetadata::get(builder.getInt32(route++)),
                llvm::ConstantAsMetadata::get(builder.getInt32(salt))}));
            use.instruction->setOperand(use.operand, load);
            ++routes;
        }
        controls += object.control_uses;
    }
    function.setMetadata("pyobf.local.inventory", llvm::MDNode::get(function.getContext(), inventory));
    function.removeFnAttr(llvm::Attribute::Memory);
    function.removeFnAttr(llvm::Attribute::Speculatable);
    coverage.preparation_metric("indexed-locals", "objects", objects.size());
    coverage.preparation_metric("indexed-locals", "address_routes", routes);
    coverage.preparation_metric("indexed-locals", "retained_control_uses", controls);
    coverage.preparation_metric("indexed-locals", "table_slots", slots);
    coverage.preparation_metric("indexed-locals", "per_invocation_bytes", function.getParent()->getDataLayout().getTypeAllocSize(array).getFixedValue());
    return routes;
}

void hoist_local_storage(llvm::Function &function) {
    std::vector<llvm::Instruction *> tables;
    for (auto &block : function) for (auto &instruction : block)
        if (instruction.getMetadata("pyobf.local.table")) tables.push_back(&instruction);
    for (auto *table : tables) if (table->getParent() != &function.getEntryBlock())
        table->moveBefore(function.getEntryBlock().getFirstInsertionPt());
}

unsigned prepare_indexed_locals(llvm::Function &function, llvm::Value *, const ResolvedRecipe &, SiteCoverage &coverage) {
    llvm::AllocaInst *table = nullptr;
    for (auto &instruction : function.getEntryBlock()) if (instruction.getMetadata("pyobf.local.table"))
        table = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
    if (table == nullptr) return 0;
    auto *array = llvm::cast<llvm::ArrayType>(table->getAllocatedType());
    std::vector<llvm::AllocaInst *> entries(array->getNumElements(), nullptr);
    for (auto &instruction : function.getEntryBlock()) if (const auto *descriptor = instruction.getMetadata("pyobf.local.object")) {
        const auto info = local_info(descriptor);
        if (!info || info->slot >= entries.size() || entries[info->slot] != nullptr)
            llvm::report_fatal_error("indexed local initialization lost its planned object layout");
        entries[info->slot] = llvm::cast<llvm::AllocaInst>(&instruction);
    }
    // Build only after structural splitting and its first SSA round. Moving an
    // initializer whose GEP was already spilled would separate it from its copies.
    llvm::IRBuilder<> builder(function.getEntryBlock().getTerminator());
    for (unsigned index = 0; index < entries.size(); ++index) {
        auto *address = llvm::cast<llvm::Instruction>(builder.CreateInBoundsGEP(array, table,
            {builder.getInt32(0), builder.getInt32(index)}, "pyobf.local.init"));
        auto *value = entries[index] == nullptr ? static_cast<llvm::Value *>(llvm::ConstantPointerNull::get(builder.getPtrTy())) : entries[index];
        auto *store = builder.CreateStore(value, address, true);
        store->setAlignment(table->getAlign());
        for (auto *instruction : {address, static_cast<llvm::Instruction *>(store)})
            instruction->setMetadata("pyobf.local.initializer", llvm::MDNode::get(function.getContext(), {}));
    }
    coverage.preparation_metric("indexed-locals", "initializer_instructions", entries.size() * 2);
    return entries.size() * 2;
}

}  // namespace pyobfuscator::native::cff
