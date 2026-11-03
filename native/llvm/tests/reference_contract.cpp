#include "reference_routes.hpp"
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
    llvm::Module module{"reference-contract", context};
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
        for (auto **function : {&target, &decoy}) {
            *function = llvm::Function::Create(type, llvm::Function::ExternalLinkage,
                function == &target ? "target" : "decoy", module);
            llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", *function));
            builder.CreateRetVoid();
        }
        caller = llvm::Function::Create(type, llvm::Function::ExternalLinkage, "caller", module);
        auto *entry = llvm::BasicBlock::Create(context, "entry", caller);
        auto *body = llvm::BasicBlock::Create(context, "body", caller);
        llvm::IRBuilder<> builder(entry);
        auto *array = llvm::ArrayType::get(builder.getPtrTy(), 4);
        table = builder.CreateAlloca(array);
        table->setMetadata("pyobf.ref.table", llvm::MDNode::get(context,
            llvm::ConstantAsMetadata::get(builder.getInt32(4))));
        state_slot = builder.CreateAlloca(builder.getInt32Ty());
        state_slot->setMetadata("pyobf.ref.state-slot", llvm::MDNode::get(context, {}));
        for (unsigned index = 0; index < 4; ++index) {
            auto *gep = llvm::cast<llvm::Instruction>(builder.CreateInBoundsGEP(array, table,
                {builder.getInt32(0), builder.getInt32(index)}));
            llvm::Value *value = index == 1 ? static_cast<llvm::Value *>(target) :
                index == 2 ? static_cast<llvm::Value *>(decoy) : llvm::ConstantPointerNull::get(builder.getPtrTy());
            initializers[index] = builder.CreateStore(value, gep, true);
            for (auto *instruction : {gep, static_cast<llvm::Instruction *>(initializers[index])})
                instruction->setMetadata("pyobf.ref.initializer", llvm::MDNode::get(context, {}));
        }
        builder.CreateStore(builder.getInt32(expected), state_slot);
        builder.CreateBr(body);
        builder.SetInsertPoint(body);
        state = builder.CreateLoad(builder.getInt32Ty(), state_slot);
        state->setMetadata("pyobf.ref.state", llvm::MDNode::get(context,
            llvm::ConstantAsMetadata::get(builder.getInt32(expected))));
        auto *mask = emit_scalar_mask(builder, builder.getInt32Ty(), state, salt, ScalarMaskDomain::reference);
        decoded = llvm::cast<llvm::BinaryOperator>(builder.CreateXor(mask, builder.getInt32(
            1 ^ scalar_mask_value(32, expected, salt, ScalarMaskDomain::reference).getZExtValue())));
        auto *index = builder.CreateAnd(decoded, builder.getInt32(3));
        address = llvm::cast<llvm::GetElementPtrInst>(builder.CreateInBoundsGEP(array, table, {builder.getInt32(0), index}));
        address->setMetadata("pyobf.ref.bound", llvm::MDNode::get(context, {
            llvm::ValueAsMetadata::get(target), llvm::ConstantAsMetadata::get(builder.getInt32(1)),
            llvm::ConstantAsMetadata::get(builder.getInt32(salt)), llvm::MDString::get(context, "call-target"),
            llvm::ConstantAsMetadata::get(builder.getInt32(expected))}));
        loaded = builder.CreateLoad(builder.getPtrTy(), address);
        loaded->setVolatile(true);
        builder.CreateCall(type, loaded);
        builder.CreateRetVoid();
        multiplier = nullptr;
        for (auto &instruction : *body)
            if (instruction.getOpcode() == llvm::Instruction::Mul)
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
        [](Fixture &f) {
            const auto value = llvm::cast<llvm::ConstantInt>(f.decoded->getOperand(1))->getZExtValue();
            f.decoded->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), value ^ 1));
        },
        [](Fixture &f) { f.address->setOperand(2, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 1)); },
        [](Fixture &f) { f.state->setMetadata("pyobf.ref.state", nullptr); },
        [](Fixture &f) { f.multiplier->setHasNoUnsignedWrap(true); },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.caller->getEntryBlock().getTerminator());
            auto *other = builder.CreateAlloca(builder.getInt32Ty());
            other->setMetadata("pyobf.ref.state-slot", llvm::MDNode::get(f.context, {}));
            f.state->setOperand(0, other);
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.caller->getEntryBlock().getTerminator());
            auto *escape = builder.CreateAlloca(builder.getPtrTy());
            builder.CreateStore(f.table, escape);
        },
        [](Fixture &f) {
            llvm::IRBuilder<> builder(f.caller->getEntryBlock().getTerminator());
            auto *gep = llvm::cast<llvm::Instruction>(builder.CreateGEP(f.table->getAllocatedType(), f.table,
                {builder.getInt32(0), builder.getInt32(1)}));
            auto *store = builder.CreateStore(f.target, gep, true);
            for (auto *instruction : {gep, static_cast<llvm::Instruction *>(store)})
                instruction->setMetadata("pyobf.ref.initializer", llvm::MDNode::get(f.context, {}));
        }
    };
    for (unsigned index = 0; index < std::size(mutations); ++index) {
        Fixture fixture;
        mutations[index](fixture);
        if (resolve_reference_target(fixture.loaded) != nullptr ||
            validate_reference_routes(*fixture.caller).empty()) return 10 + index;
    }
    finish_reference_routes(valid.module);
    if (!validate_reference_routes(*valid.caller).empty() || resolve_reference_target(valid.loaded) != nullptr)
        return 30;
    return llvm::verifyModule(valid.module) ? 31 : 0;
}
