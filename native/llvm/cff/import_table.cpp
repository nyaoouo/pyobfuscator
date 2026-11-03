#include "import_routes.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

unsigned prepare_import_routes(llvm::Function &function, llvm::Value *, const ResolvedRecipe &, SiteCoverage &) {
    unsigned count = 0;
    for (auto &block : function) for (auto &instruction : block) {
        auto *table = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
        const auto *layout = table == nullptr ? nullptr : table->getMetadata("pyobf.ref.layout");
        if (layout == nullptr) continue;
        auto *array = llvm::dyn_cast<llvm::ArrayType>(table->getAllocatedType());
        if (array == nullptr || array->getNumElements() != layout->getNumOperands())
            llvm::report_fatal_error("native import routes have invalid planned storage");
        llvm::IRBuilder<> builder(function.getEntryBlock().getTerminator());
        for (unsigned slot = 0; slot < layout->getNumOperands(); ++slot) {
            const auto *value = llvm::dyn_cast<llvm::ValueAsMetadata>(layout->getOperand(slot));
            if (value == nullptr || value->getValue()->getType() != builder.getPtrTy())
                llvm::report_fatal_error("native import routes have invalid planned targets");
            auto *address = llvm::cast<llvm::Instruction>(builder.CreateInBoundsGEP(array, table,
                {builder.getInt32(0), builder.getInt32(slot)}, "pyobf.import.init"));
            auto *store = builder.CreateStore(value->getValue(), address, true);
            store->setAlignment(table->getAlign());
            for (auto *generated : {address, static_cast<llvm::Instruction *>(store)})
                generated->setMetadata("pyobf.ref.initializer", llvm::MDNode::get(function.getContext(), {}));
            ++count;
        }
    }
    return count;
}

}  // namespace pyobfuscator::native::cff
