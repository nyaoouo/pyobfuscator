#pragma once

#include "contribution_binding_fixture.hpp"

#include <functional>
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {
inline void clean_layer_dead_code(BindingFixture &f) {
    bool changed;
    do {
        changed = false;
        for (auto iterator = f.gate->begin(); iterator != f.gate->end();) {
            auto &instruction = *iterator++;
            const auto *read = llvm::dyn_cast<llvm::LoadInst>(&instruction);
            if (instruction.use_empty() && !instruction.isTerminator() &&
                    (!instruction.mayHaveSideEffects() || (read != nullptr && read->getPointerOperand() == f.state))) {
                instruction.eraseFromParent(); changed = true;
            }
        }
    } while (changed);
}
inline void rebuild_layer_gate(BindingFixture &f, unsigned mode) {
    if (!f.layers->verify(*f.owner).empty()) llvm::report_fatal_error("layer mutant input was not valid");
    const auto update = f.update(f.gate);
    auto *normal = const_cast<llvm::Value *>(f.layers->normal_encoded(*f.gate, update.encoded));
    auto *store = const_cast<llvm::StoreInst *>(update.store);
    auto description = *read_transition_layers(store->getMetadata("pyobf.transition.layers"));
    if (mode == 0) description.models.pop_back();
    else if (mode == 1) description.models.front().seed ^= 1;
    else if (mode == 2) std::swap(description.models[0], description.models[1]);
    llvm::IRBuilder<> builder(store);
    for (const auto &spec : description.models) {
        ResolvedRecipe recipe; recipe.junk_rounds = spec.rounds;
        normal = spec.model->emit(builder, normal, f.state, description.state, spec.seed, recipe);
    }
    auto *current = const_cast<llvm::LoadInst *>(update.current);
    store->setOperand(0, builder.CreateAdd(current, decode_delta(builder, current, normal, f.layout.transition_salt)));
    store->setMetadata("pyobf.transition.layers", describe_transition_layers(f.context, description));
    clean_layer_dead_code(f);
}
inline bool check_layer_mutations() {
    for (bool grouped : {false, true}) for (unsigned seed : {1, 17, 41}) for (unsigned mask : {1, 2, 4, 7}) {
        BindingFixture f(seed, false, grouped, mask);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.contribution->verify(*f.owner).empty() ||
                !validate_contribution_gates(*f.owner).empty() || !f.flow->verify(*f.owner, f.contribution.get()).empty()) return false;
    }
    const std::pair<const char *, std::function<void(BindingFixture &)>> mutations[]{
        {"lost descriptor", [](BindingFixture &f) { const_cast<llvm::StoreInst *>(f.update(f.gate).store)->setMetadata("pyobf.transition.layers", nullptr); }},
        {"coherent removed strategy", [](BindingFixture &f) { rebuild_layer_gate(f, 0); }},
        {"coherent changed seed", [](BindingFixture &f) { rebuild_layer_gate(f, 1); }},
        {"coherent changed order", [](BindingFixture &f) { rebuild_layer_gate(f, 2); }},
        {"extra state writer", [](BindingFixture &f) {
            llvm::IRBuilder<> b(f.query); b.CreateStore(b.getInt32(f.layout.states[f.gate]), f.state);
        }},
        {"unowned volatile read", [](BindingFixture &f) {
            llvm::IRBuilder<> b(f.query); b.CreateLoad(b.getInt32Ty(), f.state)->setVolatile(true);
        }},
        {"merged opaque observations", [](BindingFixture &f) {
            llvm::LoadInst *first = nullptr, *second = nullptr;
            for (auto &instruction : *f.gate) if (auto *read = llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
                if (read->getName().starts_with("pyobf.opaque.first")) first = read;
                if (read->getName().starts_with("pyobf.opaque.second")) second = read;
            }
            second->replaceAllUsesWith(first); second->eraseFromParent();
        }},
        {"wrong decoy coefficient", [](BindingFixture &f) {
            for (auto &instruction : *f.gate) if (auto *multiply = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
                    multiply != nullptr && multiply->getName() == "pyobf.decoy.product") {
                auto *value = llvm::cast<llvm::ConstantInt>(multiply->getOperand(1));
                multiply->setOperand(1, llvm::ConstantInt::get(value->getType(), value->getZExtValue() ^ 8)); break;
            }
        }},
        {"query canceled under layers", [](BindingFixture &f) { f.query->replaceAllUsesWith(llvm::ConstantInt::get(f.query->getType(), 0)); }},
    };
    for (bool grouped : {false, true}) for (const auto &[name, mutate] : mutations) {
        BindingFixture f(17, false, grouped, 7); mutate(f);
        if (llvm::verifyModule(f.module, &llvm::errs()) ||
                (llvm::StringRef(name).starts_with("coherent ") && !validate_contribution_gates(*f.owner).empty()) ||
                f.contribution->verify(*f.owner).empty() || f.flow->verify(*f.owner, f.contribution.get()).empty()) {
            llvm::errs() << "composed layer mutant escaped or failed its required consistency boundary: " << name << "\n"; return false;
        }
    }
    for (bool grouped : {false, true}) {
        BindingFixture f(17, false, grouped, 7);
        if (!f.layers->verify(*f.owner).empty()) return false;
        auto *normal = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.layers->normal_encoded(*f.start, f.update(f.start).encoded)));
        normal->setTrueValue(normal->getFalseValue());
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.contribution->verify(*f.owner).empty() ||
                f.flow->verify(*f.owner, f.contribution.get()).empty()) return false;
    }
    llvm::outs() << "24 single/grouped strategy combinations and20 layer/flow mutants verified\n";
    return true;
}
}
