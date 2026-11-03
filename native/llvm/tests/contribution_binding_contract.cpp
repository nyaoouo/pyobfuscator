#include "contribution_binding_fixture.hpp"
#include "scalar_proof.hpp"

#include <functional>
#include <iterator>

#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include "contribution_group_mutations.hpp"
#include "transition_layer_mutations.hpp"
#include "state_binding_mutations.hpp"
#include "bogus_control_mutations.hpp"
#include "hybrid_scalar_mutations.hpp"

using namespace pyobfuscator::native::cff;
using pyobfuscator::native::cff::test::BindingFixture;

int main() {
    if (!pyobfuscator::native::cff::test::check_hybrid_scalars()) return 1;
    if (!pyobfuscator::native::cff::test::check_bogus_controls()) return 1;
    if (!pyobfuscator::native::cff::test::check_state_binding_mutations<BindingFixture>("hybrid", [](auto &f) {
        return f.flow->verify(*f.owner, f.contribution.get());
    })) return 1;
    for (unsigned seed : {1, 2, 17, 41, 255}) {
        BindingFixture f(seed);
        const auto state = f.layout.states[f.gate];
        const auto encoded = encode_delta(state, f.layout.states[f.start], f.layout.transition_salt);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.contribution->verify(*f.owner).empty() ||
                !f.flow->verify(*f.owner, f.contribution.get()).empty() || f.flow->verify(*f.owner).empty() ||
                !f.contribution->covers_unconditional(*f.gate, state, encoded) ||
                f.contribution->covers_unconditional(*f.start, state, encoded) ||
                f.contribution->covers_unconditional(*f.gate, state ^ 1, encoded) ||
                f.contribution->covers_unconditional(*f.gate, state, encoded ^ 1)) return 1;
    }
    {
        BindingFixture f(17, true);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.contribution->verify(*f.owner).empty() ||
                f.flow->verify(*f.owner, f.contribution.get()).empty()) return 1;
    }
    {
        BindingFixture f;
        const auto update = f.update(f.gate);
        auto *store = const_cast<llvm::StoreInst *>(update.store);
        llvm::IRBuilder<> builder(store);
        const auto changed_salt = f.layout.transition_salt ^ 0x10000u;
        auto *current = const_cast<llvm::LoadInst *>(update.current);
        store->setOperand(0, builder.CreateAdd(current, decode_delta(builder, current,
            const_cast<llvm::Value *>(update.encoded), changed_salt)));
        store->setMetadata("pyobf.contribution.transition", llvm::MDNode::get(f.context,
            llvm::ConstantAsMetadata::get(builder.getInt32(changed_salt))));
        if (llvm::verifyModule(f.module, &llvm::errs()) || !validate_contribution_gates(*f.owner).empty()) return 1;
        if (f.contribution->verify(*f.owner).empty()) {
            llvm::errs() << "frozen contribution decoder salt escaped despite internally consistent retained evidence\n";
            return 1;
        }
    }
    unsigned identity_mutants = 0;
    for (unsigned field : {3u, 7u, 8u, 9u, 10u}) {
        BindingFixture f;
        llvm::SmallVector<llvm::Metadata *, 11> fields;
        for (const auto &operand : f.query->getMetadata("pyobf.contribution.query")->operands()) fields.push_back(operand);
        const auto before = llvm::mdconst::extract<llvm::ConstantInt>(fields[field])->getZExtValue();
        auto *changed = llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), before + 1);
        fields[field] = llvm::ConstantAsMetadata::get(changed);
        f.query->setMetadata("pyobf.contribution.query", llvm::MDNode::get(f.context, fields));
        if (field == 3) {
            // Keep retained mask evidence self-consistent while changing its public salt.
            bool replaced = false;
            for (auto &instruction : *f.gate) {
                auto *op = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
                if (op != nullptr && op->getOpcode() == llvm::Instruction::Xor && op->getOperand(0) == f.query) {
                    op->setOperand(1, changed); replaced = true;
                }
            }
            if (!replaced) return 1;
        } else f.query->setArgOperand(field == 10 ? 5 : field - 6, changed);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !validate_contribution_gates(*f.owner).empty()) {
            llvm::errs() << "source-plan mutation is not valid internally consistent retained IR: " << field << "\n";
            return 1;
        }
        const auto reason = f.contribution->verify(*f.owner);
        if (reason != "contribution query identity differs from its frozen private source plan" ||
                f.flow->verify(*f.owner, f.contribution.get()) != reason) {
            llvm::errs() << "frozen source plan accepted coordinated query/metadata mutation: " << field << "\n";
            return 1;
        }
        ++identity_mutants;
    }
    const std::pair<const char *, std::function<void(BindingFixture &)>> mutations[]{
        {"frozen current", [](BindingFixture &f) {
            f.query->setArgOperand(6, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), f.layout.states[f.gate]));
        }},
        {"query source", [](BindingFixture &f) {
            f.query->setArgOperand(0, llvm::ConstantPointerNull::get(llvm::PointerType::getUnqual(f.context)));
        }},
        {"query result canceled", [](BindingFixture &f) {
            auto *combine = const_cast<llvm::BinaryOperator *>(llvm::cast<llvm::BinaryOperator>(f.update(f.gate).encoded));
            combine->setOperand(0, llvm::ConstantInt::get(combine->getType(), 0));
        }},
        {"consistent retained sealed target", [](BindingFixture &f) {
            auto *combine = const_cast<llvm::BinaryOperator *>(llvm::cast<llvm::BinaryOperator>(f.update(f.gate).encoded));
            const auto old = llvm::cast<llvm::ConstantInt>(combine->getOperand(1))->getZExtValue();
            auto *changed = llvm::ConstantInt::get(combine->getType(), old ^ 1); combine->setOperand(1, changed);
            llvm::SmallVector<llvm::Metadata *, 11> fields;
            for (const auto &operand : f.query->getMetadata("pyobf.contribution.query")->operands()) fields.push_back(operand);
            fields[4] = fields[5] = llvm::ConstantAsMetadata::get(changed);
            f.query->setMetadata("pyobf.contribution.query", llvm::MDNode::get(f.context, fields));
            if (!validate_contribution_gates(*f.owner).empty()) llvm::report_fatal_error("retained target mutant was not internally consistent");
        }},
        {"original decision bypass", [](BindingFixture &f) {
            auto *select = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded));
            select->setTrueValue(select->getFalseValue());
        }},
        {"invoke normal boundary", [](BindingFixture &f) { f.eh.invokes[0].instruction->setNormalDest(f.returned); }},
        {"unwind correction", [](BindingFixture &f) {
            auto *store = llvm::cast<llvm::StoreInst>(f.eh.invokes[0].instruction->getPrevNode());
            store->setOperand(0, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0));
        }},
    };
    for (const auto &[name, mutate] : mutations) {
        BindingFixture f; mutate(f);
        const auto reason = f.flow->verify(*f.owner, f.contribution.get());
        if (llvm::verifyModule(f.module, &llvm::errs()) || reason.empty()) {
            llvm::errs() << "hybrid binding mutant escaped or is invalid: " << name << "; " << reason << "\n";
            return 1;
        }
    }
    if (!pyobfuscator::native::cff::test::check_group_mutations()) return 1;
    if (!pyobfuscator::native::cff::test::check_layer_mutations()) return 1;
    llvm::outs() << "verified " << std::size(mutations) + 2 + identity_mutants << " hybrid binding/route mutants; unbound and mismatched source/normal plans refused\n";
}
