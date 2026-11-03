#include "import_routes.hpp"
#include "scalar_mask.hpp"

#include <array>
#include <functional>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

namespace {
using namespace pyobfuscator::native::cff;

struct Fixture {
    llvm::LLVMContext context;
    llvm::Module module{"import-contract", context};
    llvm::Function *caller, *target, *decoy;
    llvm::AllocaInst *table, *state_slot;
    llvm::LoadInst *state, *loaded;
    llvm::GetElementPtrInst *address;
    llvm::BinaryOperator *decoded, *multiplier;
    std::array<llvm::StoreInst *, 4> initializers;
    static constexpr std::uint32_t expected = 0x12345678u, salt = 0xc1953bf1u;

    Fixture() {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        auto *type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), {}, false);
        target = llvm::Function::Create(type, llvm::Function::ExternalLinkage, "target", module);
        decoy = llvm::Function::Create(type, llvm::Function::ExternalLinkage, "decoy", module);
        caller = llvm::Function::Create(type, llvm::Function::ExternalLinkage, "caller", module);
        auto *entry = llvm::BasicBlock::Create(context, "entry", caller);
        auto *dispatch = llvm::BasicBlock::Create(context, "dispatch", caller);
        auto *pivot = llvm::BasicBlock::Create(context, "pivot", caller);
        auto *leaf = llvm::BasicBlock::Create(context, "leaf", caller);
        auto *other_leaf = llvm::BasicBlock::Create(context, "other.leaf", caller);
        auto *body = llvm::BasicBlock::Create(context, "body", caller);
        auto *other = llvm::BasicBlock::Create(context, "other", caller);
        llvm::IRBuilder<> builder(entry);
        auto *array = llvm::ArrayType::get(builder.getPtrTy(), 4);
        table = builder.CreateAlloca(array);
        table->setAlignment(llvm::Align(8));
        table->setMetadata("pyobf.ref.table", llvm::MDNode::get(context, {
            llvm::ConstantAsMetadata::get(builder.getInt32(4)), llvm::MDString::get(context, "import-routes")}));
        state_slot = builder.CreateAlloca(builder.getInt32Ty());
        state_slot->setMetadata("pyobf.ref.state-slot", llvm::MDNode::get(context, {}));
        std::vector<llvm::Metadata *> layout;
        for (unsigned index = 0; index < 4; ++index) {
            auto *gep = llvm::cast<llvm::Instruction>(builder.CreateInBoundsGEP(array, table,
                {builder.getInt32(0), builder.getInt32(index)}));
            llvm::Value *value = index == 1 ? static_cast<llvm::Value *>(target) :
                index == 2 ? static_cast<llvm::Value *>(decoy) : llvm::ConstantPointerNull::get(builder.getPtrTy());
            layout.push_back(llvm::ValueAsMetadata::get(value));
            initializers[index] = builder.CreateStore(value, gep, true);
            initializers[index]->setAlignment(llvm::Align(8));
            for (auto *instruction : {gep, static_cast<llvm::Instruction *>(initializers[index])})
                instruction->setMetadata("pyobf.ref.initializer", llvm::MDNode::get(context, {}));
        }
        table->setMetadata("pyobf.ref.layout", llvm::MDNode::get(context, layout));
        builder.CreateStore(builder.getInt32(expected), state_slot);
        builder.CreateBr(dispatch);
        builder.SetInsertPoint(dispatch);
        auto *current = builder.CreateLoad(builder.getInt32Ty(), state_slot);
        builder.CreateBr(pivot);
        builder.SetInsertPoint(pivot);
        builder.CreateCondBr(builder.CreateICmpUGE(current, builder.getInt32(expected)), leaf, other_leaf);
        builder.SetInsertPoint(leaf); builder.CreateBr(body);
        builder.SetInsertPoint(other_leaf); builder.CreateBr(other);
        builder.SetInsertPoint(other); builder.CreateRetVoid();
        builder.SetInsertPoint(body);
        state = builder.CreateLoad(builder.getInt32Ty(), state_slot);
        state->setMetadata("pyobf.ref.state", llvm::MDNode::get(context,
            llvm::ConstantAsMetadata::get(builder.getInt32(expected))));
        auto *mask = emit_scalar_mask(builder, builder.getInt32Ty(), state, salt, ScalarMaskDomain::import_route);
        decoded = llvm::cast<llvm::BinaryOperator>(builder.CreateXor(mask, builder.getInt32(
            1 ^ scalar_mask_value(32, expected, salt, ScalarMaskDomain::import_route).getZExtValue())));
        auto *index = builder.CreateAnd(decoded, builder.getInt32(3));
        address = llvm::cast<llvm::GetElementPtrInst>(builder.CreateInBoundsGEP(array, table, {builder.getInt32(0), index}));
        address->setMetadata("pyobf.ref.bound", llvm::MDNode::get(context, {
            llvm::ValueAsMetadata::get(target), llvm::ConstantAsMetadata::get(builder.getInt32(1)),
            llvm::ConstantAsMetadata::get(builder.getInt32(salt)), llvm::MDString::get(context, "call-target"),
            llvm::ConstantAsMetadata::get(builder.getInt32(expected)), llvm::MDString::get(context, "import-routes")}));
        loaded = builder.CreateLoad(builder.getPtrTy(), address);
        loaded->setVolatile(true); loaded->setAlignment(llvm::Align(8));
        builder.CreateCall(type, loaded); builder.CreateRetVoid();
        for (auto &instruction : *body) if (instruction.getOpcode() == llvm::Instruction::Mul)
            multiplier = llvm::cast<llvm::BinaryOperator>(&instruction);
    }
};
}  // namespace

int main() {
    Fixture valid;
    if (llvm::verifyModule(valid.module) || resolve_reference_target(valid.loaded) != valid.target ||
        !validate_reference_routes(*valid.caller).empty()) return 1;
    const std::function<void(Fixture &)> mutations[]{
        [](Fixture &f) { f.initializers[1]->setOperand(0, f.decoy); },
        [](Fixture &f) { f.initializers[1]->setVolatile(false); },
        [](Fixture &f) { f.loaded->setVolatile(false); },
        [](Fixture &f) { f.initializers[0]->eraseFromParent(); },
        [](Fixture &f) { f.table->setMetadata("pyobf.ref.layout", nullptr); },
        [](Fixture &f) { f.table->setMetadata("pyobf.ref.table", nullptr); },
        [](Fixture &f) { f.loaded->setAlignment(llvm::Align(1)); },
        [](Fixture &f) { f.table->setAlignment(llvm::Align(1)); },
        [](Fixture &f) { f.target->setLinkage(llvm::Function::ExternalWeakLinkage); },
        [](Fixture &f) { f.multiplier->setHasNoUnsignedWrap(true); },
        [](Fixture &f) { f.state->setMetadata("pyobf.ref.state", nullptr); },
        [](Fixture &f) { f.address->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 1)); },
        [](Fixture &f) { f.address->setOperand(2, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 1)); },
        [](Fixture &f) {
            f.multiplier->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0));
            f.decoded->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 1));
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.caller->getEntryBlock().getTerminator());
            auto *other = builder.CreateAlloca(builder.getInt32Ty());
            other->setMetadata("pyobf.ref.state-slot", llvm::MDNode::get(f.context, {}));
            f.state->setOperand(0, other);
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.caller->getEntryBlock().getTerminator());
            auto *escape = builder.CreateAlloca(builder.getPtrTy()); builder.CreateStore(f.table, escape);
        },
        [](Fixture &f) {
            auto *tag = f.address->getMetadata("pyobf.ref.bound");
            tag->replaceOperandWith(5, llvm::MDString::get(f.context, "reference-routes"));
        },
        [](Fixture &f) {
            auto *tag = f.address->getMetadata("pyobf.ref.bound");
            tag->replaceOperandWith(0, llvm::ValueAsMetadata::get(f.decoy));
            f.initializers[1]->setOperand(0, f.decoy);
        },
        [](Fixture &f) {
            auto *tag = f.address->getMetadata("pyobf.ref.bound");
            auto *zero = llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0);
            tag->replaceOperandWith(4, llvm::ConstantAsMetadata::get(zero));
            f.state->setMetadata("pyobf.ref.state", llvm::MDNode::get(f.context, llvm::ConstantAsMetadata::get(zero)));
            f.decoded->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context),
                1 ^ scalar_mask_value(32, 0, f.salt, ScalarMaskDomain::import_route).getZExtValue()));
        },
        [](Fixture &f) {
            auto *call = llvm::cast<llvm::CallInst>(*f.loaded->user_begin()); call->eraseFromParent();
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.caller->getEntryBlock().getTerminator());
            auto *foreign = builder.CreateAlloca(builder.getPtrTy());
            auto *store = builder.CreateStore(f.target, foreign, true);
            store->setMetadata("pyobf.ref.initializer", llvm::MDNode::get(f.context, {}));
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.caller->getEntryBlock().getTerminator());
            auto *other = builder.CreateAlloca(builder.getInt32Ty());
            other->setMetadata("pyobf.ref.state-slot", llvm::MDNode::get(f.context, {}));
            f.state_slot->setMetadata("pyobf.ref.state-slot", nullptr);
            f.state->setOperand(0, other);
        },
        [](Fixture &f) {
            f.initializers[1]->setAtomic(llvm::AtomicOrdering::Monotonic);
        }
    };
    for (unsigned index = 0; index < std::size(mutations); ++index) {
        Fixture fixture; mutations[index](fixture);
        if (validate_reference_routes(*fixture.caller).empty()) {
            llvm::errs() << "import mutation unexpectedly accepted: " << index << '\n'; return 10 + index;
        }
    }
    finish_reference_routes(valid.module);
    return llvm::verifyModule(valid.module) || resolve_reference_target(valid.loaded) != nullptr ? 40 : 0;
}
