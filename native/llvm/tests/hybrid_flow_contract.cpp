#include "hybrid_flow_fixture.hpp"
#include "call_preparation.hpp"
#include "scalar_proof.hpp"

#include <algorithm>
#include <functional>
#include <iterator>

#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace pyobfuscator::native::cff;
using pyobfuscator::native::cff::test::HybridFixture;

namespace {

llvm::BinaryOperator *mask_base(HybridFixture &fixture) {
    const auto update = fixture.update(fixture.start);
    for (auto &instruction : *fixture.start)
        if (auto *operation = llvm::dyn_cast<llvm::BinaryOperator>(&instruction))
            if (operation->getOpcode() == llvm::Instruction::Xor && operation->getOperand(0) == update.current &&
                scalar_constant(operation->getOperand(1), fixture.layout.transition_salt)) return operation;
    llvm::report_fatal_error("fixture mask base was not found");
}

llvm::ICmpInst *tree_root(HybridFixture &fixture) {
    auto *node = llvm::cast<llvm::BranchInst>(fixture.dispatch->getTerminator())->getSuccessor(0);
    return llvm::cast<llvm::ICmpInst>(&node->front());
}

}  // namespace

int main() {
    for (unsigned seed : {1, 2, 17, 41, 255}) {
        HybridFixture fixture(seed);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || !fixture.seal->verify(*fixture.owner).empty()) return 1;
    }
    for (bool condition : {false, true}) {
        HybridFixture fixture(17, condition);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || !fixture.seal->verify(*fixture.owner).empty()) return 1;
    }
    {
        HybridFixture fixture;
        auto *compare = tree_root(fixture);
        const auto old = llvm::cast<llvm::ConstantInt>(compare->getOperand(1))->getZExtValue();
        std::uint32_t lower = 0, upper = UINT32_MAX;
        for (const auto &[body, state] : fixture.layout.states) {
            if (state < old) lower = std::max(lower, state);
            else upper = std::min(upper, state);
        }
        const auto changed = lower + 1 == old ? upper - 1 : lower + 1;
        if (changed == old) llvm::report_fatal_error("fixture has no alternate gap pivot");
        compare->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(fixture.context), changed));
        fixture.b->moveAfter(fixture.returned);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || !fixture.seal->verify(*fixture.owner).empty()) return 1;
    }
    const std::pair<const char *, std::function<void(HybridFixture &)>> mutations[]{
        {"same-leaf initial", [](HybridFixture &f) {
            const auto other = f.layout.states[f.start] - 1;
            if (!preparation_state_routes_to(*f.start, f.state, other)) llvm::report_fatal_error("fixture lost same-leaf counterexample");
            f.initial->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), other));
        }},
        {"condition", [](HybridFixture &f) {
            auto *select = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded));
            llvm::IRBuilder<> builder(select);
            select->setCondition(builder.CreateNot(f.owner->getArg(0)));
        }},
        {"sample-only mask", [](HybridFixture &f) {
            mask_base(f)->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), f.layout.states[f.start]));
        }},
        {"canceled state", [](HybridFixture &f) {
            const auto update = f.update(f.start);
            llvm::IRBuilder<> builder(const_cast<llvm::StoreInst *>(update.store));
            auto *target = builder.CreateSelect(f.owner->getArg(0), builder.getInt32(f.layout.states[f.a]), builder.getInt32(f.layout.states[f.b]));
            const_cast<llvm::StoreInst *>(update.store)->setOperand(0,
                builder.CreateAdd(builder.CreateMul(const_cast<llvm::LoadInst *>(update.current), builder.getInt32(0)), target));
        }},
        {"normal target", [](HybridFixture &f) {
            auto *select = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded));
            const auto *value = llvm::cast<llvm::ConstantInt>(select->getTrueValue());
            select->setTrueValue(llvm::ConstantInt::get(value->getType(), value->getZExtValue() ^ 1));
        }},
        {"duplicate state sample", [](HybridFixture &f) {
            auto *base = mask_base(f);
            llvm::IRBuilder<> builder(base);
            base->setOperand(0, builder.CreateLoad(builder.getInt32Ty(), f.state));
        }},
        {"extra state write", [](HybridFixture &f) { llvm::IRBuilder<> b(f.start->getTerminator()); b.CreateStore(b.getInt32(0), f.state); }},
        {"escaped state", [](HybridFixture &f) {
            llvm::IRBuilder<> b(f.entry->getTerminator()); auto *escape = b.CreateAlloca(b.getPtrTy()); b.CreateStore(f.state, escape);
        }},
        {"wrong arm", [](HybridFixture &f) {
            auto *arm = llvm::cast<llvm::StoreInst>(f.plan.invokes[0].instruction->getPrevNode());
            arm->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context),
                encode_delta(f.layout.states[f.b], f.layout.states[f.cleanup], f.layout.transition_salt)));
        }},
        {"extra arm", [](HybridFixture &f) {
            llvm::IRBuilder<> b(f.plan.invokes[0].instruction->getPrevNode()); b.CreateStore(b.getInt32(0), f.correction);
        }},
        {"unowned correction read", [](HybridFixture &f) { llvm::IRBuilder<> b(f.start->getTerminator()); b.CreateLoad(b.getInt32Ty(), f.correction); }},
        {"normal invoke delta", [](HybridFixture &f) {
            auto *delta = const_cast<llvm::BinaryOperator *>(llvm::cast<llvm::BinaryOperator>(
                llvm::cast<llvm::BinaryOperator>(f.update(f.gate_a).store->getValueOperand())->getOperand(1)));
            delta->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0));
        }},
        {"cached pad correction", [](HybridFixture &f) {
            auto *delta = const_cast<llvm::BinaryOperator *>(llvm::cast<llvm::BinaryOperator>(
                llvm::cast<llvm::BinaryOperator>(f.update(f.pad).store->getValueOperand())->getOperand(1)));
            delta->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context),
                encode_delta(f.layout.states[f.a], f.layout.states[f.cleanup], f.layout.transition_salt)));
        }},
        {"volatile state", [](HybridFixture &f) { const_cast<llvm::LoadInst *>(f.update(f.start).current)->setVolatile(true); }},
        {"wrapping promise", [](HybridFixture &f) { llvm::cast<llvm::BinaryOperator>(const_cast<llvm::Value *>(f.update(f.start).store->getValueOperand()))->setHasNoUnsignedWrap(true); }},
        {"normal gateway bypass", [](HybridFixture &f) { llvm::cast<llvm::BranchInst>(f.gate_a->getTerminator())->setSuccessor(0, f.returned); }},
        {"equality dispatcher", [](HybridFixture &f) { tree_root(f)->setPredicate(llvm::CmpInst::ICMP_EQ); }},
        {"signedness promise", [](HybridFixture &f) { tree_root(f)->setSameSign(true); }},
        {"cyclic tree", [](HybridFixture &f) {
            auto *root = tree_root(f)->getParent(); llvm::cast<llvm::BranchInst>(root->getTerminator())->setSuccessor(0, root);
        }},
        {"shared subtree", [](HybridFixture &f) {
            auto *branch = llvm::cast<llvm::BranchInst>(tree_root(f)->getParent()->getTerminator());
            branch->setSuccessor(0, branch->getSuccessor(1));
        }},
        {"wrong leaf", [](HybridFixture &f) {
            for (auto &body : *f.owner) if (auto *branch = llvm::dyn_cast<llvm::BranchInst>(body.getTerminator()))
                if (branch->isUnconditional() && branch->getSuccessor(0) == f.start) {
                    branch->setSuccessor(0, f.returned); return;
                }
            llvm::report_fatal_error("fixture has no start leaf");
        }},
        {"empty partition", [](HybridFixture &f) {
            tree_root(f)->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0));
        }},
        {"duplicate dispatcher sample", [](HybridFixture &f) {
            auto *compare = tree_root(f); llvm::IRBuilder<> b(compare); compare->setOperand(0, b.CreateLoad(b.getInt32Ty(), f.state));
        }},
        {"exact-state pivot", [](HybridFixture &f) {
            auto *compare = tree_root(f); const auto old = llvm::cast<llvm::ConstantInt>(compare->getOperand(1))->getZExtValue();
            std::uint32_t upper = UINT32_MAX;
            for (const auto &[body, state] : f.layout.states) if (state >= old) upper = std::min(upper, state);
            compare->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), upper));
        }},
        {"unplanned block", [](HybridFixture &f) { llvm::IRBuilder<>(llvm::BasicBlock::Create(f.context, "extra", f.owner)).CreateRetVoid(); }},
        {"state alignment", [](HybridFixture &f) { f.state->setAlignment(llvm::Align(8)); }},
        {"invoke target", [](HybridFixture &f) {
            auto *other = llvm::Function::Create(f.plan.invokes[0].instruction->getFunctionType(),
                llvm::Function::ExternalLinkage, "other", f.module);
            f.plan.invokes[0].instruction->setCalledFunction(other);
        }},
        {"resume operand", [](HybridFixture &f) {
            auto *resume = llvm::cast<llvm::ResumeInst>(f.cleanup->getTerminator()); resume->setOperand(0, llvm::UndefValue::get(resume->getValue()->getType()));
        }},
        {"same-leaf data label", [](HybridFixture &f) {
            llvm::IRBuilder<> b(f.context); const auto other = f.layout.states[f.start] - 1;
            const_cast<llvm::LoadInst *>(f.update(f.start).current)->setMetadata("pyobf.ref.state",
                llvm::MDNode::get(f.context, llvm::ConstantAsMetadata::get(b.getInt32(other))));
        }},
    };
    for (const auto &[name, mutate] : mutations) {
        HybridFixture fixture;
        mutate(fixture);
        const auto old_reason = verify_hybrid_eh(fixture.plan, *fixture.owner);
        const auto reason = fixture.seal->verify(*fixture.owner);
        if (llvm::verifyModule(fixture.module, &llvm::errs()) || !old_reason.empty() || reason.empty()) {
            llvm::errs() << "hybrid flow mutant escaped or was not a valid old-guard counterexample: " << name
                         << "; old=" << old_reason << "; flow=" << reason << "\n";
            return 1;
        }
    }
    llvm::outs() << "verified " << std::size(mutations) << " hybrid flow mutants\n";
    return 0;
}
