#include "indexed_locals.hpp"
#include "call_frames.hpp"
#include "scalar_mask.hpp"
#include "site_report.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

unsigned bind_indexed_locals(llvm::BasicBlock &body, llvm::Value *state_slot, std::uint32_t expected_state,
                               std::uint32_t, SiteCoverage *coverage) {
    unsigned count = 0;
    for (auto &instruction : body) {
        const auto *pending = instruction.getMetadata("pyobf.local.pending");
        if (pending == nullptr) continue;
        const auto *descriptor = pending->getNumOperands() == 3 ? llvm::dyn_cast<llvm::MDNode>(pending->getOperand(0)) : nullptr;
        const auto info = local_info(descriptor);
        const auto route = frame_number(pending, 1), salt = frame_number(pending, 2);
        auto *load = llvm::dyn_cast<llvm::LoadInst>(&instruction);
        auto *table = load == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
        auto *array = table == nullptr ? nullptr : llvm::dyn_cast<llvm::ArrayType>(table->getAllocatedType());
        if (!info || !route || !salt || *route >= info->routes || load == nullptr || !load->isVolatile() || load->isAtomic() ||
            array == nullptr || !array->getElementType()->isPointerTy() || info->slot >= array->getNumElements() ||
            array->getNumElements() < 2 || (array->getNumElements() & (array->getNumElements() - 1)))
            llvm::report_fatal_error("indexed locals have an invalid pending address");
        llvm::IRBuilder<> builder(load);
        auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.local.state");
        state->setMetadata("pyobf.local.state", llvm::MDNode::get(body.getContext(),
            llvm::ConstantAsMetadata::get(builder.getInt32(expected_state))));
        llvm::cast<llvm::Instruction>(state_slot)->setMetadata("pyobf.local.state-slot", llvm::MDNode::get(body.getContext(), {}));
        auto *mask = emit_scalar_mask(builder, builder.getInt32Ty(), state, *salt, ScalarMaskDomain::local);
        const auto encoded = info->slot ^ static_cast<std::uint32_t>(
            scalar_mask_value(32, expected_state, *salt, ScalarMaskDomain::local).getZExtValue());
        auto *decoded = builder.CreateXor(mask, builder.getInt32(encoded), "pyobf.local.decode");
        auto *index = builder.CreateAnd(decoded, builder.getInt32(array->getNumElements() - 1), "pyobf.local.index");
        auto *address = llvm::cast<llvm::Instruction>(builder.CreateInBoundsGEP(array, table,
            {builder.getInt32(0), index}, "pyobf.local.slot"));
        for (auto *control = static_cast<llvm::Instruction *>(state); control != address; control = control->getNextNode())
            control->setMetadata("pyobf.local.control", llvm::MDNode::get(body.getContext(), {}));
        address->setMetadata("pyobf.local.bound", llvm::MDNode::get(body.getContext(), {
            const_cast<llvm::MDNode *>(descriptor), llvm::ConstantAsMetadata::get(builder.getInt32(*route)),
            llvm::ConstantAsMetadata::get(builder.getInt32(*salt)), llvm::ConstantAsMetadata::get(builder.getInt32(expected_state))}));
        load->setOperand(0, address);
        load->setMetadata("pyobf.local.pending", nullptr);
        if (coverage != nullptr && *route == 0) {
            llvm::AllocaInst *object = nullptr;
            for (auto &entry_instruction : body.getParent()->getEntryBlock())
                if (entry_instruction.getMetadata("pyobf.local.object") == descriptor) object = llvm::dyn_cast<llvm::AllocaInst>(&entry_instruction);
            if (object == nullptr) llvm::report_fatal_error("indexed local route lost its source object");
            coverage->applied("indexed-locals", *object);
            auto *type = object->getAllocatedType();
            coverage->record_type("indexed-locals", type->isIntegerTy() ? "i" + std::to_string(type->getIntegerBitWidth()) :
                type->isArrayTy() ? "array" : type->isStructTy() ? "struct" : type->isVectorTy() ? "vector" :
                type->isPointerTy() ? "pointer" : "floating");
        }
        ++count;
    }
    return count;
}

}  // namespace pyobfuscator::native::cff
