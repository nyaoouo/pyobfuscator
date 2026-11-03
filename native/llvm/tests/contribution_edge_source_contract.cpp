#include "contribution_edge_source_fixture.hpp"

#include <functional>
#include <iterator>

#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace pyobfuscator::native::cff;
using pyobfuscator::native::cff::test::EdgeSourceFixture;

int main() {
    for (unsigned seed : {1, 2, 17, 41, 255}) {
        EdgeSourceFixture f(seed);
        if (llvm::verifyModule(f.module, &llvm::errs())) return 1;
        f.lower();
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.plan->verify_sources(*f.owner).empty()) return 1;
    }
    {
        EdgeSourceFixture f;
        llvm::cast<llvm::BranchInst>(f.entry->getTerminator())->setSuccessor(0, f.gateway(1));
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.plan->before_lowering(*f.owner).empty()) return 1;
    }
    const std::pair<const char *, std::function<void(EdgeSourceFixture &)>> mutations[]{
        {"original branch bypass", [](EdgeSourceFixture &f) {
            llvm::cast<llvm::BranchInst>(f.entry->getTerminator())->setSuccessor(0, f.gateway(1));
        }},
        {"gateway target", [](EdgeSourceFixture &f) {
            llvm::cast<llvm::BranchInst>(f.gateway(0)->getTerminator())->setSuccessor(0, f.right);
        }},
        {"query identity", [](EdgeSourceFixture &f) {
            auto *call = llvm::cast<llvm::CallInst>(&f.gateway(0)->front());
            call->setArgOperand(4, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0));
        }},
        {"query source", [](EdgeSourceFixture &f) {
            llvm::cast<llvm::CallInst>(&f.gateway(0)->front())->setArgOperand(0, llvm::ConstantPointerNull::get(llvm::PointerType::getUnqual(f.context)));
        }},
        {"switch case target", [](EdgeSourceFixture &f) { f.first_case()->setSuccessor(0, f.right); }},
        {"switch case value", [](EdgeSourceFixture &f) {
            llvm::cast<llvm::ICmpInst>(f.first_case()->getCondition())->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 99));
        }},
        {"switch default", [](EdgeSourceFixture &f) {
            auto *last = llvm::cast<llvm::BranchInst>(f.first_case()->getSuccessor(1)->getTerminator());
            last->setSuccessor(1, f.right);
        }},
        {"switch condition store", [](EdgeSourceFixture &f) {
            auto *store = llvm::cast<llvm::StoreInst>(f.switched->getTerminator()->getPrevNode());
            store->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0));
        }},
        {"switch extra writer", [](EdgeSourceFixture &f) {
            llvm::IRBuilder<> b(f.first_case()); b.CreateStore(b.getInt32(0), f.slot());
        }},
        {"switch storage escape", [](EdgeSourceFixture &f) {
            auto *slot = f.slot();
            llvm::IRBuilder<> b(&*f.entry->getFirstInsertionPt()); auto *escape = b.CreateAlloca(b.getPtrTy());
            b.SetInsertPoint(f.first_case()); b.CreateStore(slot, escape);
        }},
    };
    for (const auto &[name, mutate] : mutations) {
        EdgeSourceFixture f; f.lower(); mutate(f);
        const auto reason = f.plan->verify_sources(*f.owner);
        if (llvm::verifyModule(f.module, &llvm::errs()) || reason.empty()) {
            llvm::errs() << "automatic edge source mutant escaped or is invalid: " << name << "; " << reason << "\n";
            return 1;
        }
    }
    llvm::outs() << "verified duplicate-successor PHI repair and " << std::size(mutations) + 1 << " automatic edge source mutants\n";
}
