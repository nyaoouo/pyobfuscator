#pragma once

#include "opaque_expression.hpp"
#include "transition_model.hpp"
#include "scalar_mask.hpp"

#include <functional>

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {
struct PredicateFixture {
    llvm::LLVMContext context;
    llvm::Module module{"predicate-contract", context};
    llvm::Function *owner;
    llvm::BasicBlock *body;
    llvm::AllocaInst *slot;
    llvm::Value *predicate;
    std::unique_ptr<TransitionModel> model;
    bool hidden;
    PredicateFixture(unsigned salt = 17, std::uint32_t expected = 0x13579bdfu, bool literals = false) : hidden(literals) {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        llvm::IRBuilder<> b(context);
        owner = llvm::Function::Create(llvm::FunctionType::get(b.getInt1Ty(), {b.getInt32Ty()}, false),
            llvm::Function::ExternalLinkage, "predicate_owner", module);
        body = llvm::BasicBlock::Create(context, "entry", owner); b.SetInsertPoint(body);
        slot = b.CreateAlloca(b.getInt32Ty()); b.CreateStore(owner->getArg(0), slot);
        predicate = emit_opaque_true(b, slot, salt, salt % 3);
        if (hidden) for (auto iterator = body->begin(); iterator != body->end();) {
            auto &instruction = *iterator++;
            if (!llvm::isa<llvm::BinaryOperator, llvm::ICmpInst>(instruction)) continue;
            for (unsigned index = 0; index != instruction.getNumOperands(); ++index)
                if (const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(index))) {
                    llvm::IRBuilder<> decode(&instruction);
                    instruction.setOperand(index, emit_scalar_literal(decode, *constant, slot, expected, 0x12345678u));
                }
        }
        b.CreateRet(predicate);
        const auto uses = slot->getNumUses(); const auto blocks = owner->size();
        model = std::make_unique<TransitionModel>(*owner, expected, salt,
            hidden ? std::optional<std::uint32_t>(0x12345678u) : std::nullopt);
        if (slot->getNumUses() != uses || owner->size() != blocks)
            llvm::report_fatal_error("predicate model mutated its actual owner");
    }
    bool matches() const {
        std::set<const llvm::LoadInst *> reads;
        if (!model->match_predicate(predicate, slot, *body, reads)) {
            if (!reads.empty()) llvm::report_fatal_error("failed predicate published state-read authority");
            return false;
        }
        unsigned observations = 0;
        for (const auto *read : reads) observations += read->isVolatile();
        return observations == 2 && (hidden ? reads.size() > 2 : reads.size() == 2) &&
            model->match(predicate, slot, *body, reads) == nullptr;
    }
};
inline bool check_predicate_models() {
    for (unsigned salt : {1, 2, 17, 41, 255}) for (std::uint32_t state : {0u, 1u, 0x80000000u, 0xffffffffu}) for (bool hidden : {false, true}) {
        PredicateFixture f(salt, state, hidden);
        if (!f.model->valid() || llvm::verifyModule(f.module, &llvm::errs()) || !f.matches()) return false;
    }
    const std::pair<const char *, std::function<void(PredicateFixture &)>> changes[]{
        {"constant predicate", [](auto &f) { f.predicate = llvm::ConstantInt::getTrue(f.context); }},
        {"volatile erasure", [](auto &f) { for (auto &i : *f.body) if (auto *r = llvm::dyn_cast<llvm::LoadInst>(&i)) { r->setVolatile(false); break; } }},
        {"merged observations", [](auto &f) {
            llvm::LoadInst *first = nullptr;
            for (auto &i : *f.body) if (auto *r = llvm::dyn_cast<llvm::LoadInst>(&i)) {
                if (first == nullptr) first = r; else { r->replaceAllUsesWith(first); r->eraseFromParent(); break; }
            }
        }},
        {"foreign root", [](auto &f) {
            llvm::IRBuilder<> b(&f.body->front()); auto *other = b.CreateAlloca(b.getInt32Ty()); b.CreateStore(b.getInt32(7), other);
            for (auto &i : *f.body) if (auto *r = llvm::dyn_cast<llvm::LoadInst>(&i)) { r->setOperand(0, other); break; }
        }},
        {"changed predicate", [](auto &f) { llvm::cast<llvm::ICmpInst>(f.predicate)->setPredicate(llvm::CmpInst::ICMP_EQ); }},
        {"poison flag", [](auto &f) { for (auto &i : *f.body) if (auto *op = llvm::dyn_cast<llvm::BinaryOperator>(&i);
            op != nullptr && op->getOpcode() == llvm::Instruction::Mul) { op->setHasNoUnsignedWrap(true); break; } }},
        {"alignment", [](auto &f) { for (auto &i : *f.body) if (auto *r = llvm::dyn_cast<llvm::LoadInst>(&i)) { r->setAlignment(llvm::Align(2)); break; } }},
        {"changed salt", [](auto &f) { f.model = std::make_unique<TransitionModel>(*f.owner, 0x13579bdfu, 18); }},
    };
    for (const auto &[name, change] : changes) {
        PredicateFixture f; change(f);
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.matches()) {
            llvm::errs() << "predicate model mutant escaped: " << name << "\n"; return false;
        }
    }
    {
        PredicateFixture f(17, 0x13579bdfu, true);
        f.model = std::make_unique<TransitionModel>(*f.owner, 0x13579bdfu, 17, 0x12345679u);
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.matches()) return false;
    }
    llvm::outs() << "40 pure/decoded predicate/reference positives and9 graph/observation/codec mutants verified\n";
    return true;
}
}
