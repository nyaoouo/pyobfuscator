#include "indexed_locals.hpp"
#include "scalar_mask.hpp"

#include <array>
#include <functional>

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace {
using namespace pyobfuscator::native::cff;

struct Fixture {
    llvm::LLVMContext context;
    llvm::Module module{"indexed-local-contract", context};
    llvm::Function *function;
    llvm::AllocaInst *a, *b, *table, *state_slot;
    llvm::MDNode *a_descriptor, *b_descriptor;
    std::array<llvm::StoreInst *, 4> initializers;
    std::vector<llvm::LoadInst *> routes, states;
    std::vector<llvm::GetElementPtrInst *> addresses;

    explicit Fixture(bool hybrid = false) {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        auto *word = llvm::Type::getInt32Ty(context);
        function = llvm::Function::Create(llvm::FunctionType::get(word, {word}, false),
            llvm::Function::ExternalLinkage, "owner", module);
        function->addFnAttr("pyobf.cff.transformed");
        llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", function));
        a = builder.CreateAlloca(word, nullptr, "a"); a->setAlignment(llvm::Align(16));
        b = builder.CreateAlloca(word, nullptr, "b"); b->setAlignment(llvm::Align(32));
        a->setMetadata("pyobf.cff.site", llvm::MDNode::get(context, llvm::MDString::get(context, "input.a")));
        b->setMetadata("pyobf.cff.site", llvm::MDNode::get(context, llvm::MDString::get(context, "input.b")));
        a_descriptor = local_descriptor(*a, 1, 2, 2); b_descriptor = local_descriptor(*b, 3, 2, 0);
        a->setMetadata("pyobf.local.object", a_descriptor); b->setMetadata("pyobf.local.object", b_descriptor);
        function->setMetadata("pyobf.local.inventory", llvm::MDNode::get(context, {a_descriptor, b_descriptor}));
        auto *array = llvm::ArrayType::get(builder.getPtrTy(), 4);
        table = builder.CreateAlloca(array); table->setAlignment(llvm::Align(8));
        table->setMetadata("pyobf.local.table", llvm::MDNode::get(context, llvm::ConstantAsMetadata::get(builder.getInt32(4))));
        state_slot = builder.CreateAlloca(word);
        state_slot->setMetadata("pyobf.local.state-slot", llvm::MDNode::get(context, {}));
        for (unsigned index = 0; index < 4; ++index) {
            auto *address = llvm::cast<llvm::Instruction>(builder.CreateInBoundsGEP(array, table, {builder.getInt32(0), builder.getInt32(index)}));
            auto *target = index == 1 ? static_cast<llvm::Value *>(a) : index == 3 ? static_cast<llvm::Value *>(b) : llvm::ConstantPointerNull::get(builder.getPtrTy());
            initializers[index] = builder.CreateStore(target, address, true);
            for (auto *instruction : {address, static_cast<llvm::Instruction *>(initializers[index])})
                instruction->setMetadata("pyobf.local.initializer", llvm::MDNode::get(context, {}));
        }
        auto *first = llvm::BasicBlock::Create(context, "first", function);
        auto *second = llvm::BasicBlock::Create(context, "second", function);
        auto *dispatch = llvm::BasicBlock::Create(context, "dispatch", function);
        auto *compare = llvm::BasicBlock::Create(context, "compare", function);
        auto *left = llvm::BasicBlock::Create(context, "left", function);
        auto *right = llvm::BasicBlock::Create(context, "right", function);
        builder.CreateLifetimeStart(a);
        builder.CreateStore(builder.getInt32(100), state_slot); builder.CreateBr(dispatch);
        const auto route = [&](llvm::MDNode *descriptor, unsigned slot, unsigned index, unsigned expected) {
            const auto salt = 0xc1856b71u + routes.size();
            auto *state = builder.CreateLoad(word, state_slot); states.push_back(state);
            state->setMetadata("pyobf.local.state", llvm::MDNode::get(context, llvm::ConstantAsMetadata::get(builder.getInt32(expected))));
            auto *mask = emit_scalar_mask(builder, word, state, salt, ScalarMaskDomain::local);
            const auto encoded = slot ^ static_cast<std::uint32_t>(scalar_mask_value(32, expected, salt, ScalarMaskDomain::local).getZExtValue());
            auto *decoded = builder.CreateXor(mask, builder.getInt32(encoded));
            auto *bounded = builder.CreateAnd(decoded, builder.getInt32(3));
            auto *address = llvm::cast<llvm::GetElementPtrInst>(builder.CreateInBoundsGEP(array, table, {builder.getInt32(0), bounded}));
            address->setMetadata("pyobf.local.bound", llvm::MDNode::get(context, {descriptor,
                llvm::ConstantAsMetadata::get(builder.getInt32(index)), llvm::ConstantAsMetadata::get(builder.getInt32(salt)),
                llvm::ConstantAsMetadata::get(builder.getInt32(expected))}));
            addresses.push_back(address);
            auto *load = builder.CreateLoad(builder.getPtrTy(), address); load->setVolatile(true); routes.push_back(load);
            return load;
        };
        builder.SetInsertPoint(first);
        builder.CreateStore(function->getArg(0), route(a_descriptor, 1, 0, 100));
        builder.CreateStore(builder.getInt32(42), route(b_descriptor, 3, 0, 100));
        if (hybrid) {
            auto *personality = llvm::Function::Create(llvm::FunctionType::get(word, true),
                llvm::Function::ExternalLinkage, "__gxx_personality_seh0", module);
            function->setPersonalityFn(personality);
            auto *target = llvm::Function::Create(llvm::FunctionType::get(builder.getVoidTy(), false),
                llvm::Function::ExternalLinkage, "may_throw", module);
            auto *normal = llvm::BasicBlock::Create(context, "normal", function);
            auto *pad = llvm::BasicBlock::Create(context, "pad", function);
            builder.CreateInvoke(target, normal, pad, {});
            builder.SetInsertPoint(pad);
            auto *exception = builder.CreateLandingPad(llvm::StructType::get(context,
                {builder.getPtrTy(), word}), 0);
            exception->setCleanup(true);
            builder.CreateStore(builder.getInt32(200), state_slot); builder.CreateBr(dispatch);
            builder.SetInsertPoint(normal);
        }
        builder.CreateStore(builder.getInt32(200), state_slot); builder.CreateBr(dispatch);
        builder.SetInsertPoint(second);
        auto *av = builder.CreateLoad(word, route(a_descriptor, 1, 1, 200));
        auto *bv = builder.CreateLoad(word, route(b_descriptor, 3, 1, 200));
        builder.CreateLifetimeEnd(a);
        builder.CreateRet(builder.CreateAdd(av, bv));
        builder.SetInsertPoint(dispatch); auto *state = builder.CreateLoad(word, state_slot); builder.CreateBr(compare);
        builder.SetInsertPoint(compare); builder.CreateCondBr(builder.CreateICmpUGE(state, builder.getInt32(200)), right, left);
        builder.SetInsertPoint(left); builder.CreateBr(first);
        builder.SetInsertPoint(right); builder.CreateBr(second);
    }

    void change_a_routes(unsigned count) {
        llvm::IRBuilder<> builder(context);
        auto *changed = local_descriptor(*a, 1, count, 2);
        a->setMetadata("pyobf.local.object", changed);
        function->setMetadata("pyobf.local.inventory", llvm::MDNode::get(context, {changed, b_descriptor}));
        for (auto *address : addresses) {
            const auto *tag = address->getMetadata("pyobf.local.bound");
            if (tag->getOperand(0) == a_descriptor) address->setMetadata("pyobf.local.bound", llvm::MDNode::get(context,
                {changed, tag->getOperand(1).get(), tag->getOperand(2).get(), tag->getOperand(3).get()}));
        }
    }
};
}  // namespace

int check(bool hybrid) {
    Fixture baseline(hybrid);
    if (llvm::verifyModule(baseline.module) || !verify_indexed_locals(baseline.module).empty()) {
        llvm::errs() << verify_indexed_locals(baseline.module) << '\n'; return 1;
    }
    const std::function<void(Fixture &)> mutations[]{
        [](Fixture &f) { f.initializers[1]->setOperand(0, f.b); },
        [](Fixture &f) { f.initializers[1]->setVolatile(false); },
        [](Fixture &f) { f.initializers[1]->setMetadata("pyobf.local.initializer", nullptr); },
        [](Fixture &f) { f.a->setMetadata("pyobf.local.object", nullptr); },
        [](Fixture &f) { f.a->setAlignment(llvm::Align(8)); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.context); f.a->setOperand(0, b.getInt32(2)); },
        [](Fixture &f) { f.function->setMetadata("pyobf.local.inventory", nullptr); },
        [](Fixture &f) { f.function->setMetadata("pyobf.local.inventory", llvm::MDNode::get(f.context, {f.a_descriptor, f.a_descriptor})); },
        [](Fixture &f) { f.function->removeFnAttr("pyobf.cff.transformed"); },
        [](Fixture &f) { f.addresses[0]->setMetadata("pyobf.local.bound", nullptr); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.context); f.addresses[0]->setOperand(2, b.getInt32(1)); },
        [](Fixture &f) { llvm::cast<llvm::BinaryOperator>(f.addresses[0]->getOperand(2))->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0)); },
        [](Fixture &f) {
            auto *bounded = llvm::cast<llvm::BinaryOperator>(f.addresses[0]->getOperand(2));
            auto *decoded = llvm::cast<llvm::BinaryOperator>(bounded->getOperand(0));
            decoded->setOperand(1, llvm::ConstantInt::get(decoded->getType(), 0));
        },
        [](Fixture &f) {
            for (auto &block : *f.function) for (auto &i : block) if (i.getMetadata("pyobf.cff.public-coefficient")) {
                i.setOperand(1, llvm::ConstantInt::get(i.getType(), 3)); return;
            }
        },
        [](Fixture &f) { llvm::IRBuilder<> b(f.addresses[0]); auto *v = f.addresses[0]->getOperand(2);
            f.addresses[0]->setOperand(2, b.CreateXor(v, b.CreateXor(v, b.getInt32(1)))); },
        [](Fixture &f) { llvm::IRBuilder<> b(&*f.function->getEntryBlock().getFirstInsertionPt());
            f.states[0]->setOperand(0, b.CreateAlloca(b.getInt32Ty())); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.context);
            f.states[0]->setMetadata("pyobf.local.state", llvm::MDNode::get(f.context, llvm::ConstantAsMetadata::get(b.getInt32(200)))); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.context); f.addresses[0]->setOperand(1, b.getInt32(1)); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.context);
            f.table->setMetadata("pyobf.local.table", llvm::MDNode::get(f.context, llvm::ConstantAsMetadata::get(b.getInt32(2)))); },
        [](Fixture &f) { f.a->setMetadata("pyobf.cff.site", llvm::MDNode::get(f.context, llvm::MDString::get(f.context, "input.other"))); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.context); auto *tag = f.addresses[2]->getMetadata("pyobf.local.bound");
            f.addresses[2]->setMetadata("pyobf.local.bound", llvm::MDNode::get(f.context,
                {tag->getOperand(0).get(), llvm::ConstantAsMetadata::get(b.getInt32(0)), tag->getOperand(2).get(), tag->getOperand(3).get()})); },
        [](Fixture &f) { f.change_a_routes(3); },
        [](Fixture &f) { f.routes[0]->setVolatile(false); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.initializers[0]); b.CreateStore(b.getInt32(7), f.a); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.initializers[1]); b.CreateStore(f.a, f.initializers[1]->getPointerOperand(), true); },
        [](Fixture &f) { auto *store = llvm::cast<llvm::StoreInst>(*f.routes[0]->user_begin());
            store->setOperand(1, llvm::ConstantPointerNull::get(llvm::PointerType::getUnqual(f.context))); },
        [](Fixture &f) { f.routes[0]->setAlignment(llvm::Align(64)); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.initializers[0]); auto *leak = new llvm::GlobalVariable(f.module, b.getPtrTy(), false,
            llvm::GlobalValue::PrivateLinkage, llvm::ConstantPointerNull::get(b.getPtrTy())); b.CreateStore(f.table, leak); },
        [](Fixture &f) { llvm::IRBuilder<> b(f.initializers[0]); auto *leak = new llvm::GlobalVariable(f.module, b.getPtrTy(), false,
            llvm::GlobalValue::PrivateLinkage, llvm::ConstantPointerNull::get(b.getPtrTy())); b.CreateStore(f.state_slot, leak); },
        [](Fixture &f) { f.routes[0]->setMetadata("pyobf.local.pending", llvm::MDNode::get(f.context, {})); },
        [](Fixture &f) {
            llvm::IRBuilder<> b(f.context); auto *tag = f.addresses[0]->getMetadata("pyobf.local.bound");
            f.states[0]->setMetadata("pyobf.local.state", llvm::MDNode::get(f.context, llvm::ConstantAsMetadata::get(b.getInt32(200))));
            f.addresses[0]->setMetadata("pyobf.local.bound", llvm::MDNode::get(f.context,
                {tag->getOperand(0).get(), tag->getOperand(1).get(), tag->getOperand(2).get(), llvm::ConstantAsMetadata::get(b.getInt32(200))}));
            auto *bounded = llvm::cast<llvm::BinaryOperator>(f.addresses[0]->getOperand(2));
            auto *decoded = llvm::cast<llvm::BinaryOperator>(bounded->getOperand(0));
            decoded->setOperand(1, b.getInt32(1u ^ scalar_mask_value(32, 200, 0xc1856b71u, ScalarMaskDomain::local).getZExtValue()));
        },
        [](Fixture &f) { f.states[0]->setMetadata("pyobf.local.initializer", llvm::MDNode::get(f.context, {})); },
        [](Fixture &f) {
            for (auto &block : *f.function) for (auto &instruction : block)
                if (local_control_use(instruction)) {
                    llvm::cast<llvm::CallInst>(instruction).setArgOperand(0, f.b); return;
                }
        }
    };
    for (unsigned index = 0; index < std::size(mutations); ++index) {
        Fixture fixture(hybrid); mutations[index](fixture);
        if (llvm::verifyModule(fixture.module, &llvm::errs())) {
            llvm::errs() << "local mutation is not valid IR: " << index << '\n'; return 60;
        }
        if (verify_indexed_locals(fixture.module).empty()) { llvm::errs() << "local mutation unexpectedly accepted: " << index << '\n'; return 10 + index; }
    }
    strip_indexed_locals(baseline.module);
    return llvm::verifyModule(baseline.module) || !verify_indexed_locals(baseline.module).empty() ? 50 : 0;
}

int main() {
    if (const auto result = check(false)) return result;
    return check(true);
}
