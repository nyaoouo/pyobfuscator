#include "reference_routes.hpp"
#include "scalar_mask.hpp"
#include "site_report.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

unsigned bind_reference_component(llvm::BasicBlock &body, llvm::Value *state_slot,
                                     std::uint32_t expected_state, SiteCoverage *coverage, bool imported) {
    unsigned count = 0;
    for (auto iterator = body.begin(); iterator != body.end();) {
        auto &instruction = *iterator++;
        const auto *tag = instruction.getMetadata("pyobf.ref.pending");
        if (tag == nullptr) continue;
        auto *address = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction);
        const auto info = reference_info(tag, false);
        if (!info) llvm::report_fatal_error("native reference routes have invalid pending metadata");
        if (info->imported != imported) continue;
        auto *load = imported ? llvm::dyn_cast<llvm::LoadInst>(&instruction) :
            address == nullptr || !address->hasOneUse() ? nullptr : llvm::dyn_cast<llvm::LoadInst>(*address->user_begin());
        auto *table = imported && load != nullptr ? llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand()) : nullptr;
        auto *array = imported ? table == nullptr ? nullptr : llvm::dyn_cast<llvm::ArrayType>(table->getAllocatedType()) :
            address == nullptr ? nullptr : llvm::dyn_cast<llvm::ArrayType>(address->getSourceElementType());
        if (array == nullptr || load == nullptr || !load->isVolatile() || (!imported && address->getNumIndices() != 2) ||
            array->getNumElements() < 2 || array->getNumElements() > 4096 ||
            (array->getNumElements() & (array->getNumElements() - 1)) || info->slot >= array->getNumElements())
            llvm::report_fatal_error("native reference routes: invalid prepared reference");
        llvm::IRBuilder<> builder(imported ? static_cast<llvm::Instruction *>(load) : address);
        auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.reference.state");
        state->setMetadata("pyobf.ref.state", llvm::MDNode::get(body.getContext(),
            llvm::ConstantAsMetadata::get(builder.getInt32(expected_state))));
        llvm::cast<llvm::Instruction>(state_slot)->setMetadata("pyobf.ref.state-slot", llvm::MDNode::get(body.getContext(), {}));
        const auto domain = imported ? ScalarMaskDomain::import_route : ScalarMaskDomain::reference;
        auto *mask = emit_scalar_mask(builder, builder.getInt32Ty(), state, info->salt, domain);
        const auto encoded = info->slot ^ static_cast<std::uint32_t>(
            scalar_mask_value(32, expected_state, info->salt, domain).getZExtValue());
        auto *decoded = builder.CreateXor(mask, builder.getInt32(encoded), "pyobf.reference.decode");
        auto *index = builder.CreateAnd(decoded, builder.getInt32(array->getNumElements() - 1), "pyobf.reference.index");
        if (imported) {
            address = llvm::cast<llvm::GetElementPtrInst>(builder.CreateInBoundsGEP(array, table,
                {builder.getInt32(0), index}, "pyobf.import.address"));
            load->setOperand(0, address);
        }
        for (auto *control = static_cast<llvm::Instruction *>(state); control != address; control = control->getNextNode())
            control->setMetadata("pyobf.ref.control", llvm::MDNode::get(body.getContext(), {}));
        address->setOperand(2, index);
        instruction.setMetadata("pyobf.ref.pending", nullptr);
        std::vector<llvm::Metadata *> bound{
            llvm::ValueAsMetadata::get(const_cast<llvm::Function *>(info->target)),
            llvm::ConstantAsMetadata::get(builder.getInt32(info->slot)),
            llvm::ConstantAsMetadata::get(builder.getInt32(info->salt)),
            llvm::MDString::get(body.getContext(), info->call_target ? "call-target" : "function-address"),
            llvm::ConstantAsMetadata::get(builder.getInt32(expected_state))};
        if (imported) bound.push_back(llvm::MDString::get(body.getContext(), "import-routes"));
        address->setMetadata("pyobf.ref.bound", llvm::MDNode::get(body.getContext(), bound));
        if (coverage != nullptr) {
            const auto component = imported ? "import-routes" : "reference-routes";
            coverage->applied(component, *load);
            coverage->record_type(component, info->call_target ? "call-target" : "function-address");
        }
        ++count;
    }
    return count;
}

unsigned bind_reference_routes(llvm::BasicBlock &body, llvm::Value *state_slot,
    std::uint32_t expected, std::uint32_t, SiteCoverage *coverage) {
    return bind_reference_component(body, state_slot, expected, coverage, false);
}

}  // namespace pyobfuscator::native::cff
