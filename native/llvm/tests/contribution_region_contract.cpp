#include "contribution_region_fixture.hpp"

#include <functional>
#include <iterator>

#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace pyobfuscator::native::cff;
using pyobfuscator::native::cff::test::RegionFixture;

int main() {
    for (unsigned seed : {1, 2, 17, 41}) for (bool at_entry : {false, true}) {
        RegionFixture f(seed, at_entry);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.flow->verify(*f.owner).empty() ||
                !f.boundary->verify(*f.owner, *f.setup, *f.state).empty()) return 1;
    }
    const std::pair<const char *, std::function<void(RegionFixture &)>> outside[]{
        {"admission bypass", [](RegionFixture &f) { llvm::cast<llvm::BranchInst>(f.prefix_a->getTerminator())->setSuccessor(0, f.start); }},
        {"outside call operand", [](RegionFixture &f) { f.outside_call->setArgOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0)); }},
        {"outside call attributes", [](RegionFixture &f) { f.outside_call->setDoesNotThrow(); }},
        {"outside volatile load", [](RegionFixture &f) { f.outside_read->setVolatile(true); }},
        {"outside inserted effect", [](RegionFixture &f) { llvm::IRBuilder<> b(f.prefix_a->getTerminator()); b.CreateStore(b.getInt32(0), f.outside_read->getPointerOperand()); }},
    };
    for (const auto &[name, mutate] : outside) {
        RegionFixture f; mutate(f);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.flow->verify(*f.owner).empty() ||
                f.boundary->verify(*f.owner, *f.setup, *f.state).empty()) { llvm::errs() << "outside boundary mutant escaped: " << name << "\n"; return 1; }
    }
    const std::pair<const char *, std::function<void(RegionFixture &)>> inside[]{
        {"reset state", [](RegionFixture &f) { f.initial->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0)); }},
        {"exit bypass", [](RegionFixture &f) { llvm::cast<llvm::BranchInst>(f.exit_leaf->getTerminator())->setSuccessor(0, f.left); }},
        {"extra reset writer", [](RegionFixture &f) { llvm::IRBuilder<> b(f.initial); b.CreateStore(b.getInt32(0), f.state); }},
        {"decision route", [](RegionFixture &f) {
            auto *choice = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded)); choice->setTrueValue(choice->getFalseValue());
        }},
        {"dispatcher bypass", [](RegionFixture &f) { llvm::cast<llvm::BranchInst>(f.dispatch->getTerminator())->setSuccessor(0, f.exit_leaf); }},
    };
    for (const auto &[name, mutate] : inside) {
        RegionFixture f; mutate(f);
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.flow->verify(*f.owner).empty() ||
                !f.boundary->verify(*f.owner, *f.setup, *f.state).empty()) { llvm::errs() << "region flow mutant escaped: " << name << "\n"; return 1; }
    }
    llvm::outs() << "verified " << std::size(outside) + std::size(inside) << " independent region boundary/flow mutants; snapshots preserve CFG and canonical spill users\n";
}
