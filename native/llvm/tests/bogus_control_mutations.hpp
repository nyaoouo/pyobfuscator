#pragma once

#include "bogus_control_fixture.hpp"
#include <functional>
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {
inline bool check_bogus_controls() {
    for (unsigned seed : {1, 2, 17, 41}) for (bool hidden : {false, true}) {
        BogusControlFixture f(seed, hidden);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.verify().empty() || !f.retained() ||
                !f.controls->owns_state_write(*f.work)) return false;
    }
    const std::pair<const char *, std::function<void(BogusControlFixture &)>> mutations[]{
        {"constant bypass", [](auto &f) { f.choice()->setCondition(llvm::ConstantInt::getTrue(f.context)); }},
        {"wrong normal arm", [](auto &f) { f.choice()->setTrueValue(llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0)); }},
        {"wrong fake arm", [](auto &f) { f.choice()->setFalseValue(llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0)); }},
        {"wrong work result", [](auto &f) { f.work->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0)); }},
        {"merged observations", [](auto &f) {
            llvm::LoadInst *first = nullptr;
            for (auto &i : *f.guard) if (auto *r = llvm::dyn_cast<llvm::LoadInst>(&i); r != nullptr && r->isVolatile()) {
                if (first == nullptr) first = r; else { r->replaceAllUsesWith(first); r->eraseFromParent(); break; }
            }
        }},
        {"foreign state", [](auto &f) {
            llvm::IRBuilder<> b(&f.entry->front()); auto *other = b.CreateAlloca(b.getInt32Ty()); b.CreateStore(b.getInt32(0), other);
            for (auto &i : *f.guard) if (auto *r = llvm::dyn_cast<llvm::LoadInst>(&i); r != nullptr && r->isVolatile()) { r->setOperand(0, other); break; }
        }},
        {"volatile erasure", [](auto &f) { for (auto &i : *f.guard) if (auto *r = llvm::dyn_cast<llvm::LoadInst>(&i); r != nullptr && r->isVolatile()) { r->setVolatile(false); break; } }},
        {"normal state write", [](auto &f) { llvm::IRBuilder<> b(f.normal->getTerminator()); b.CreateStore(b.getInt32(0), f.state); }},
        {"decoy state write", [](auto &f) { llvm::IRBuilder<> b(f.work); b.CreateStore(b.getInt32(0), f.state); }},
        {"descriptor erasure", [](auto &f) { f.predicate->setMetadata("pyobf.bogus.guard", nullptr); }},
        {"inventory erasure", [](auto &f) { f.owner->removeFnAttr("pyobf.bogus.controls"); }},
        {"wrong entry", [](auto &f) { llvm::cast<llvm::StoreInst>(f.entry->getTerminator()->getPrevNode())->setOperand(0,
            llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), f.layout.states[f.decoy])); }},
        {"work RAUW", [](auto &f) {
            auto *old = f.work; llvm::IRBuilder<> b(old); auto *next = b.CreateStore(f.result, f.state);
            next->setMetadata("pyobf.bogus.work", old->getMetadata("pyobf.bogus.work")); old->eraseFromParent(); f.work = next;
        }},
        {"coherent provenance", [](auto &f) {
            const auto *old = f.predicate->getMetadata("pyobf.bogus.guard");
            llvm::SmallVector<llvm::Metadata *, 11> fields;
            for (unsigned i = 0; i != 10; ++i) fields.push_back(old->getOperand(i));
            fields.push_back(llvm::MDString::get(f.context, "other-source"));
            auto *tag = llvm::MDNode::get(f.context, fields); f.predicate->setMetadata("pyobf.bogus.guard", tag); f.work->setMetadata("pyobf.bogus.work", tag);
        }},
    };
    for (const auto &[name, mutate] : mutations) {
        BogusControlFixture f;
        if (!f.verify().empty()) return false;
        mutate(f);
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.verify().empty()) {
            llvm::errs() << "bogus control/normal-flow mutant escaped: " << name << "\n"; return false;
        }
        if (std::string(name) != "normal state write" && std::string(name) != "decoy state write" &&
                std::string(name) != "wrong entry" && f.controls->owns_state_write(*f.work)) {
            llvm::errs() << "failed control proof retained state-writer authority\n"; return false;
        }
        if ((std::string(name) == "work RAUW" || std::string(name) == "coherent provenance") && !f.retained()) {
            llvm::errs() << "coherent shape mutant did not distinguish private-plan authority\n"; return false;
        }
    }
    llvm::outs() << "8 raw/decoded bogus-control/normal-flow positives and14 valid-IR bypass/ownership/private-plan mutants verified\n";
    return true;
}
}
