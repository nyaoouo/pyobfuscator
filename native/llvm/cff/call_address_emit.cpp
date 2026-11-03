#include "call_preparation.hpp"
#include "scalar_mask.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

llvm::GetElementPtrInst *emit_prepared_address(llvm::GetElementPtrInst &address, llvm::Value *state_slot,
                                               std::uint32_t expected_state) {
    auto &body = *address.getParent();
    const auto *pending = address.getMetadata("pyobf.prep.pending");
    const auto *descriptor = pending != nullptr && pending->getNumOperands() == 3 ? llvm::dyn_cast<llvm::MDNode>(pending->getOperand(0)) : nullptr;
    const auto info = read_frame_metadata(descriptor);
    const auto field = frame_number(pending, 1), salt = frame_number(pending, 2);
    const auto placement = info && field ? frame_placement(body.getModule()->getDataLayout(), info->layout, *field) :
        std::optional<FramePlacement>{};
    if (!info || !field || !salt || !placement) llvm::report_fatal_error("invalid prepared call frame address");
    llvm::IRBuilder<> builder(&address);
    auto *state = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.preparation.state");
    state->setMetadata("pyobf.prep.state", llvm::MDNode::get(body.getContext(),
        llvm::ConstantAsMetadata::get(builder.getInt32(expected_state))));
    llvm::cast<llvm::Instruction>(state_slot)->setMetadata("pyobf.prep.state-slot", llvm::MDNode::get(body.getContext(), {}));
    auto *mask = emit_scalar_mask(builder, builder.getInt32Ty(), state, *salt, ScalarMaskDomain::preparation);
    const auto encoded = (placement->offset / placement->alignment) ^ static_cast<std::uint32_t>(
        scalar_mask_value(32, expected_state, *salt, ScalarMaskDomain::preparation).getZExtValue());
    auto *decoded = builder.CreateXor(mask, builder.getInt32(encoded), "pyobf.preparation.decode");
    auto *index = builder.CreateURem(decoded, builder.getInt32(placement->placements), "pyobf.preparation.index");
    auto *offset = builder.CreateMul(index, builder.getInt32(placement->alignment), "pyobf.preparation.offset");
    auto *bound = llvm::cast<llvm::GetElementPtrInst>(builder.CreateGEP(
        builder.getInt8Ty(), address.getPointerOperand(), offset, "pyobf.preparation.field"));
    for (auto *control = static_cast<llvm::Instruction *>(state); control != bound; control = control->getNextNode())
        control->setMetadata("pyobf.prep.control", llvm::MDNode::get(body.getContext(), {}));
    bound->setMetadata("pyobf.prep.bound", llvm::MDNode::get(body.getContext(), {
        const_cast<llvm::MDNode *>(descriptor), llvm::ConstantAsMetadata::get(builder.getInt32(*field)),
        llvm::ConstantAsMetadata::get(builder.getInt32(*salt)),
        llvm::ConstantAsMetadata::get(builder.getInt32(expected_state))}));
    return bound;
}

}  // namespace pyobfuscator::native::cff
