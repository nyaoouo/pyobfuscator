#include "contribution_edge_flow_fixture.hpp"
#include "contribution_parallel_mutations.hpp"
#include "state_binding_mutations.hpp"

#include <functional>
#include <iterator>

#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace pyobfuscator::native::cff;
using pyobfuscator::native::cff::test::EdgeFlowFixture;

int main() {
    if (!test::check_parallel_contribution_flow()) return 1;
    if (!pyobfuscator::native::cff::test::check_state_binding_mutations<EdgeFlowFixture>("whole", [](auto &f) {
        return f.seal->verify(*f.owner);
    })) return 1;
    for (unsigned seed : {1, 2, 17, 41, 255}) {
        EdgeFlowFixture fixture(seed);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || !fixture.seal->verify(*fixture.owner).empty()) return 1;
    }
    for (bool condition : {false, true}) {
        EdgeFlowFixture fixture(17, condition);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || !fixture.seal->verify(*fixture.owner).empty()) return 1;
    }
    const std::pair<const char *, std::function<void(EdgeFlowFixture &)>> mutations[]{
        {"bypass gateway", [](EdgeFlowFixture &f) {
            auto *choice = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded));
            choice->setTrueValue(llvm::ConstantInt::get(choice->getType(), encode_delta(f.layout.states[f.start],
                f.layout.states[f.left], f.layout.transition_salt)));
        }},
        {"decision condition", [](EdgeFlowFixture &f) {
            auto *choice = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded));
            llvm::IRBuilder<> builder(choice); choice->setCondition(builder.CreateNot(f.owner->getArg(0)));
        }},
        {"swapped arms", [](EdgeFlowFixture &f) {
            auto *choice = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded));
            auto *yes = choice->getTrueValue(); choice->setTrueValue(choice->getFalseValue()); choice->setFalseValue(yes);
        }},
        {"initial state", [](EdgeFlowFixture &f) {
            f.initial->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), f.layout.states[f.gateway]));
        }},
        {"dispatcher bypass", [](EdgeFlowFixture &f) {
            llvm::cast<llvm::BranchInst>(f.dispatch->getTerminator())->setSuccessor(0, f.left);
        }},
        {"dispatcher partition", [](EdgeFlowFixture &f) {
            auto *root = llvm::cast<llvm::BranchInst>(f.dispatch->getTerminator())->getSuccessor(0);
            llvm::cast<llvm::ICmpInst>(&root->front())->setPredicate(llvm::CmpInst::ICMP_ULT);
        }},
        {"extra state writer", [](EdgeFlowFixture &f) {
            llvm::IRBuilder<> b(f.start->getTerminator()); b.CreateStore(b.getInt32(0), f.state);
        }},
        {"state escape", [](EdgeFlowFixture &f) {
            llvm::IRBuilder<> b(&*f.entry->getFirstInsertionPt()); auto *escape = b.CreateAlloca(b.getPtrTy());
            b.SetInsertPoint(f.start->getTerminator()); b.CreateStore(f.state, escape);
        }},
        {"terminal replaced", [](EdgeFlowFixture &f) {
            auto *old = f.returned->getTerminator(); llvm::IRBuilder<> b(old); b.CreateBr(f.dispatch); old->eraseFromParent();
        }},
        {"unplanned body", [](EdgeFlowFixture &f) {
            llvm::IRBuilder<>(llvm::BasicBlock::Create(f.context, "extra", f.owner)).CreateRetVoid();
        }},
        {"unchecked current", [](EdgeFlowFixture &f) {
            auto *store = const_cast<llvm::StoreInst *>(f.update(f.gateway).store);
            store->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), f.layout.states[f.left]));
        }},
        {"overflow annotation", [](EdgeFlowFixture &f) {
            const_cast<llvm::BinaryOperator *>(llvm::cast<llvm::BinaryOperator>(f.update(f.gateway).store->getValueOperand()))->setHasNoUnsignedWrap();
        }},
    };
    for (const auto &[name, mutate] : mutations) {
        EdgeFlowFixture fixture; mutate(fixture);
        const auto reason = fixture.seal->verify(*fixture.owner);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || reason.empty()) {
            llvm::errs() << "automatic edge flow mutant escaped or is invalid: " << name << "; " << reason << "\n";
            return 1;
        }
    }
    llvm::outs() << "verified " << std::size(mutations) << " automatic edge flow mutants\n";
}
