#pragma once

#include "contribution_binding_fixture.hpp"
#include "contribution_mix.hpp"
#include "path_fold.hpp"

#include <functional>
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {
inline void replace_group_expression(BindingFixture &f, bool reorder) {
    const auto update = f.update(f.gate);
    auto *store = const_cast<llvm::StoreInst *>(update.store);
    llvm::IRBuilder<> builder(store);
    llvm::SmallVector<llvm::Metadata *, 32> fields;
    for (const auto &operand : f.query->getMetadata("pyobf.contribution.query")->operands()) fields.push_back(operand);
    const auto word = [&](unsigned index) { return llvm::mdconst::extract<llvm::ConstantInt>(fields[index])->getZExtValue(); };
    if (reorder) {
        std::swap(fields[13], fields[17]); fields[10] = fields[13];
    } else fields[11] = llvm::ConstantAsMetadata::get(builder.getInt32(word(11) ^ 1));
    const auto domain = word(11);
    const auto calls = contribution_group_queries(*f.gate);
    std::vector<std::pair<std::uint32_t, std::uint32_t>> labels;
    std::vector<llvm::Value *> values;
    for (unsigned index = 0; index != calls.size(); ++index) {
        const auto label = word(13 + 2 * index), encoding = word(14 + 2 * index);
        auto *query = const_cast<llvm::CallInst *>(calls[index]);
        query->setArgOperand(5, builder.getInt32(label)); labels.push_back({label, encoding}); values.push_back(query);
    }
    auto *actual = emit_contribution_mix(builder, plan_contribution_mix(domain, word(9), word(1), labels), values);
    auto *encoded = builder.CreateXor(emit_path_fold_word(builder, actual, 0, word(3)), builder.getInt32(word(4)));
    auto *current = const_cast<llvm::LoadInst *>(update.current);
    store->setOperand(0, builder.CreateAdd(current, decode_delta(builder, current, encoded, f.layout.transition_salt)));
    f.query->setMetadata("pyobf.contribution.query", llvm::MDNode::get(f.context, fields));
}
inline bool check_group_mutations() {
    for (unsigned seed : {1, 2, 17, 41, 255}) {
        BindingFixture f(seed, false, true);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.contribution->verify(*f.owner).empty() ||
                !f.flow->verify(*f.owner, f.contribution.get()).empty()) return false;
    }
    const std::pair<const char *, std::function<void(BindingFixture &)>> mutations[]{
        {"missing member", [](BindingFixture &f) {
            auto *source = const_cast<llvm::CallInst *>(contribution_group_queries(*f.gate)[1]);
            source->replaceAllUsesWith(llvm::ConstantInt::get(source->getType(), 0));
        }},
        {"duplicate member value", [](BindingFixture &f) {
            auto calls = contribution_group_queries(*f.gate);
            const_cast<llvm::CallInst *>(calls[1])->replaceAllUsesWith(const_cast<llvm::CallInst *>(calls[0]));
        }},
        {"different lease", [](BindingFixture &f) {
            auto *source = const_cast<llvm::CallInst *>(contribution_group_queries(*f.gate)[1]);
            source->setArgOperand(0, llvm::ConstantPointerNull::get(llvm::PointerType::getUnqual(f.context)));
        }},
        {"wrong ordinal", [](BindingFixture &f) {
            auto *source = const_cast<llvm::CallInst *>(contribution_group_queries(*f.gate)[1]);
            source->setMetadata("pyobf.contribution.source", f.query->getMetadata("pyobf.contribution.source"));
        }},
        {"different current", [](BindingFixture &f) {
            auto *source = const_cast<llvm::CallInst *>(contribution_group_queries(*f.gate)[1]);
            source->setArgOperand(6, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), f.layout.states[f.gate]));
        }},
        {"interleaved root writer", [](BindingFixture &f) {
            llvm::IRBuilder<> builder(const_cast<llvm::CallInst *>(contribution_group_queries(*f.gate)[1]));
            builder.CreateStore(builder.getInt32(f.layout.states[f.gate]), f.state);
        }},
        {"retained reordered sources", [](BindingFixture &f) { replace_group_expression(f, true); }},
        {"retained changed mixing domain", [](BindingFixture &f) { replace_group_expression(f, false); }},
        {"replacement acquisition", [](BindingFixture &f) {
            auto *source = const_cast<llvm::CallInst *>(contribution_group_queries(*f.gate)[1]);
            auto *replacement = llvm::cast<llvm::CallInst>(source->clone()); replacement->insertBefore(source->getIterator());
            source->replaceAllUsesWith(replacement); source->eraseFromParent();
        }},
    };
    for (const auto &[name, mutate] : mutations) {
        BindingFixture f(17, false, true); mutate(f);
        const bool coherent = llvm::StringRef(name).starts_with("retained ") || llvm::StringRef(name) == "replacement acquisition";
        if (llvm::verifyModule(f.module, &llvm::errs()) || (coherent && !validate_contribution_gates(*f.owner).empty()) ||
                f.contribution->verify(*f.owner).empty() || f.flow->verify(*f.owner, f.contribution.get()).empty()) {
            llvm::errs() << "grouped source mutation escaped or failed its required consistency boundary: " << name << "\n";
            return false;
        }
    }
    llvm::outs() << "verified9 grouped source/dataflow/private-plan mutations and5 seed positives\n";
    return true;
}
}
