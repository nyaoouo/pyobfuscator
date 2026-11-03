#include "transition_model.hpp"
#include "recipe.hpp"
#include "cff.hpp"
#include "transition_registry.hpp"
#include "transition_predicate_mutations.hpp"

#include <functional>

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace pyobfuscator::native::cff;
namespace {
struct Fixture {
    llvm::LLVMContext context;
    llvm::Module module{"layer-model", context};
    llvm::Function *owner;
    llvm::BasicBlock *body;
    llvm::AllocaInst *state;
    llvm::Value *actual;
    llvm::Value *normal;
    Component component{};
    ResolvedRecipe recipe;
    std::unique_ptr<TransitionModel> model;
    Fixture(unsigned strategy, unsigned seed, std::uint32_t expected, bool constant = false) {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        llvm::IRBuilder<> b(context);
        owner = llvm::Function::Create(llvm::FunctionType::get(b.getInt32Ty(), {b.getInt32Ty(), b.getInt32Ty()}, false),
            llvm::Function::ExternalLinkage, "layer_owner", module);
        body = llvm::BasicBlock::Create(context, "entry", owner); b.SetInsertPoint(body);
        state = b.CreateAlloca(b.getInt32Ty()); state->setAlignment(llvm::Align(4)); b.CreateStore(owner->getArg(1), state);
        auto *end = b.CreateUnreachable();
        end->setMetadata("pyobf.cff.site", llvm::MDNode::get(context, llvm::MDString::get(context, "source:branch")));
        const char *names[]{"opaque-choices", "reachable-junk", "decoy-transitions"};
        component.name = names[strategy]; component.transition_model = find_transition_model(component.name);
        component.transition = strategy == 0 ? select_opaque_transition : strategy == 1 ? apply_reachable_junk : select_decoy_transition;
        recipe.junk_rounds = seed % 5 + 1;
        model = std::make_unique<TransitionModel>(*owner, component, "source:branch", expected, seed, recipe);
        b.SetInsertPoint(end); normal = constant ? static_cast<llvm::Value *>(b.getInt32(0x2468ace0)) : owner->getArg(0);
        actual = component.transition(b, normal, state, expected, seed, recipe);
        b.CreateRet(actual); end->eraseFromParent();
    }
    bool matches() {
        std::set<const llvm::LoadInst *> reads;
        return model->match(actual, state, *body, reads) == normal && !reads.empty();
    }
};
}
int main() {
    if (!pyobfuscator::native::cff::test::check_predicate_models()) return 1;
    for (unsigned strategy = 0; strategy != 3; ++strategy) for (unsigned seed : {1, 17, 41, 255})
        for (std::uint32_t state : {0u, 1u, 0x80000000u, 0xffffffffu}) for (bool constant : {false, true}) {
            Fixture f(strategy, seed, state, constant);
            if (!f.model->valid() || llvm::verifyModule(f.module, &llvm::errs()) || !f.matches()) {
                llvm::errs() << "valid transition model failed: " << f.component.name << "; " << f.model->error() << "\n"; return 1;
            }
        }
    unsigned mutants = 0;
    {
        Fixture f(0, 17, 0x13579bdf);
        llvm::LoadInst *first = nullptr, *second = nullptr;
        for (auto &instruction : *f.body) if (auto *read = llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
            if (first == nullptr) first = read; else { second = read; break; }
        }
        second->replaceAllUsesWith(first); second->eraseFromParent();
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.matches()) return 1;
        ++mutants;
    }
    for (unsigned strategy = 0; strategy != 3; ++strategy) {
        const std::function<void(Fixture &)> changes[]{
            [](Fixture &f) { f.owner->getArg(0)->replaceAllUsesWith(llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0)); },
            [](Fixture &f) { for (auto &i : *f.body) if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&i)) { load->setVolatile(!load->isVolatile()); break; } },
            [](Fixture &f) { llvm::IRBuilder<> b(&f.body->front()); auto *other = b.CreateAlloca(b.getInt32Ty()); b.CreateStore(b.getInt32(0), other);
                for (auto &i : *f.body) if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&i)) { load->setOperand(0, other); break; } },
            [](Fixture &f) { for (auto &i : *f.body) if (auto *compare = llvm::dyn_cast<llvm::ICmpInst>(&i)) { compare->setPredicate(llvm::ICmpInst::ICMP_EQ); break; }
                else if (auto *binary = llvm::dyn_cast<llvm::BinaryOperator>(&i); binary != nullptr && binary->getOpcode() == llvm::Instruction::Mul) { binary->setHasNoUnsignedWrap(true); break; } },
        };
        for (const auto &change : changes) {
            Fixture f(strategy, 17, 0x13579bdf); change(f);
            if (llvm::verifyModule(f.module, &llvm::errs()) || f.matches()) { llvm::errs() << "transition model mutant escaped\n"; return 1; }
            ++mutants;
        }
    }
    Fixture f(0, 17, 7);
    for (bool cancel : {false, true}) {
        auto component = f.component;
        component.transition = +[](llvm::IRBuilder<> &b, llvm::Value *normal, llvm::Value *, std::uint32_t, std::uint32_t, const ResolvedRecipe &) {
            return b.CreateXor(normal, normal);
        };
        if (!cancel) component.transition = +[](llvm::IRBuilder<> &b, llvm::Value *, llvm::Value *, std::uint32_t, std::uint32_t, const ResolvedRecipe &) -> llvm::Value * { return b.getInt32(0); };
        TransitionModelRegistration registration{component.name, component.transition}; component.transition_model = &registration;
        TransitionModel invalid(*f.owner, component, "source:branch", 7, 17, f.recipe);
        if (invalid.valid()) return 1;
    }
    llvm::outs() << "96 symbolic/constant entry-identity/template positives, " << mutants << " graph mutants and2 invalid registrations verified\n";
}
