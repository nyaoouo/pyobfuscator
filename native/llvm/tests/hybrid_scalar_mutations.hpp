#pragma once

#include "hybrid_scalar_fixture.hpp"
#include <functional>
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {
inline bool check_hybrid_scalars() {
    for (unsigned width : {1, 2, 7, 8, 16, 31, 32, 33, 64, 65, 128}) for (unsigned seed : {1, 2, 17, 41}) {
        HybridScalarFixture f(width, seed);
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.owns() || !f.verify().empty() || !f.owns() ||
                f.seal->verify(*f.owner).empty() || f.binding->preserves_terminal_operand(*f.ret, 1, f.literal, f.decoded)) return false;
        TransitionModel model(*f.owner, *f.literal, f.layout.states[f.returned], 0x12345678u);
        std::set<const llvm::LoadInst *> reads;
        if (!model.valid() || model.match(f.decoded, f.state, *f.returned, reads) != nullptr || !reads.empty() ||
                model.match_predicate(f.decoded, f.state, *f.returned, reads) || !reads.empty()) return false;
    }
    const std::pair<const char *, std::function<void(HybridScalarFixture &)>> mutants[]{
        {"constant bypass", [](auto &f) { f.ret->setOperand(0, const_cast<llvm::ConstantInt *>(f.literal)); }},
        {"wrong literal", [](auto &f) { f.ret->setOperand(0, llvm::ConstantInt::get(f.literal->getType(), 1)); }},
        {"foreign root", [](auto &f) { for (auto &i : *f.returned) if (auto *read = llvm::dyn_cast<llvm::LoadInst>(&i)) { read->setOperand(0, f.correction); break; } }},
        {"volatile read", [](auto &f) { for (auto &i : *f.returned) if (auto *read = llvm::dyn_cast<llvm::LoadInst>(&i)) { read->setVolatile(true); break; } }},
        {"wrong encoded word", [](auto &f) {
            auto *op = llvm::cast<llvm::BinaryOperator>(f.decoded);
            const auto *old = llvm::cast<llvm::ConstantInt>(op->getOperand(0));
            op->setOperand(0, llvm::ConstantInt::get(old->getType(), old->getValue() ^ 1));
        }},
        {"extra identity", [](auto &f) { llvm::IRBuilder<> b(f.ret); f.ret->setOperand(0, b.CreateAdd(f.decoded, llvm::ConstantInt::get(f.literal->getType(), 0))); }},
        {"wrong state", [](auto &f) {
            llvm::IRBuilder<> b(f.ret);
            f.ret->setOperand(0, emit_scalar_literal(b, *f.literal, f.state, f.layout.states[f.returned] ^ 1, 0x12345678u));
        }},
        {"wrong seed", [](auto &f) {
            llvm::IRBuilder<> b(f.ret);
            f.ret->setOperand(0, emit_scalar_literal(b, *f.literal, f.state, f.layout.states[f.returned], 0x12345679u));
        }},
        {"metadata bypass", [](auto &f) {
            f.ret->setMetadata("pyobf.hybrid.scalar.verified", llvm::MDNode::get(f.context, {}));
            f.ret->setOperand(0, const_cast<llvm::ConstantInt *>(f.literal));
        }},
        {"return replacement", [](auto &f) {
            auto *old = f.ret; auto *next = llvm::ReturnInst::Create(f.context, f.decoded, old);
            old->eraseFromParent(); f.ret = next;
        }},
        {"unplanned writer", [](auto &f) { llvm::IRBuilder<> b(f.ret); b.CreateStore(b.getInt32(0), f.state); }},
        {"changed resume", [](auto &f) {
            auto *resume = f.cleanup->getTerminator();
            resume->setOperand(0, llvm::Constant::getNullValue(resume->getOperand(0)->getType()));
        }},
    };
    for (const auto &[name, mutate] : mutants) {
        HybridScalarFixture f;
        if (!f.verify().empty() || !f.owns()) return false;
        mutate(f);
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.verify().empty()) {
            llvm::errs() << "hybrid scalar/flow mutant escaped: " << name << "\n"; return false;
        }
        if (std::string(name) != "unplanned writer" && std::string(name) != "changed resume" && f.owns()) {
            llvm::errs() << "failed scalar model retained operand authority\n"; return false;
        }
    }
    {
        HybridScalarFixture f;
        if (!f.verify().empty()) return false;
        auto *other = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(f.context), false),
            llvm::Function::ExternalLinkage, "other", f.module);
        llvm::IRBuilder<>(llvm::BasicBlock::Create(f.context, "entry", other)).CreateRetVoid();
        if (f.binding->verify(*other).empty() || f.owns() || !f.verify().empty() || !f.owns()) return false;
    }
    {
        HybridFixture f(17, std::nullopt, 129);
        const auto *literal = llvm::cast<llvm::ConstantInt>(f.returned->getTerminator()->getOperand(0));
        TransitionModel unsupported(*f.owner, *literal, f.layout.states[f.returned], 17);
        if (unsupported.valid()) return false;
    }
    llvm::outs() << "44 typed hybrid literal positives,12 valid-IR scalar/flow mutants, owner-cache reset and width refusal verified\n";
    return true;
}
}
