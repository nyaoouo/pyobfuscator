#pragma once

#include "cff.hpp"
#include "contribution_gate.hpp"
#include "contribution_private.hpp"
#include "contribution_groups.hpp"
#include "transition_layers.hpp"
#include "transition_registry.hpp"
#include "hybrid_flow.hpp"
#include "state_layout.hpp"
#include "transition_encode.hpp"
#include "transition_proof.hpp"

#include <memory>

#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff::test {
struct BindingFixture {
    llvm::LLVMContext context;
    llvm::Module module{"contribution-binding", context};
    llvm::Function *owner;
    llvm::BasicBlock *entry, *gate, *start, *a, *b, *returned, *pad, *cleanup, *normal_a, *normal_b, *dispatch;
    llvm::AllocaInst *state;
    llvm::CallInst *query;
    HybridEhPlan eh;
    StateLayout layout;
    ResolvedRecipe recipe;
    std::unique_ptr<TransitionLayers> layers;
    std::unique_ptr<ContributionGateSeal> contribution;
    std::unique_ptr<HybridFlowSeal> flow;

    explicit BindingFixture(unsigned seed = 17, bool inconsistent_plan = false, bool grouped = false, unsigned composition = 0) {
        module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
        module.setTargetTriple(llvm::Triple("x86_64-w64-windows-gnu"));
        llvm::IRBuilder<> builder(context);
        owner = llvm::Function::Create(llvm::FunctionType::get(builder.getVoidTy(), {builder.getInt1Ty(), builder.getPtrTy()}, false),
            llvm::Function::ExternalLinkage, "binding_flow", module);
        auto *personality = llvm::Function::Create(llvm::FunctionType::get(builder.getInt32Ty(), true),
            llvm::Function::ExternalLinkage, "__gxx_personality_seh0", module);
        owner->setPersonalityFn(personality); eh.personality = personality;
        auto *target = llvm::Function::Create(llvm::FunctionType::get(builder.getVoidTy(), false),
            llvm::Function::ExternalLinkage, "target", module);
        const auto block = [&](const char *name) { return llvm::BasicBlock::Create(context, name, owner); };
        entry = block("entry"); gate = block("gate"); start = block("start"); a = block("a"); b = block("b");
        returned = block("returned"); pad = block("pad"); cleanup = block("cleanup");
        normal_a = block("normal.a"); normal_b = block("normal.b"); dispatch = block("dispatch");
        builder.SetInsertPoint(entry);
        state = builder.CreateAlloca(builder.getInt32Ty()); state->setAlignment(llvm::Align(4));
        state->setMetadata("pyobf.contribution.root", llvm::MDNode::get(context, {}));
        eh.unwind_correction = builder.CreateAlloca(builder.getInt32Ty());
        auto *exception_type = llvm::StructType::get(context, {builder.getPtrTy(), builder.getInt32Ty()});
        auto *saved = builder.CreateAlloca(exception_type); builder.CreateBr(gate);
        builder.SetInsertPoint(gate);
        auto helper = module.getOrInsertFunction("pyobf_native_contribution_word_v1", llvm::FunctionType::get(builder.getInt32Ty(),
            {builder.getPtrTy(), builder.getInt32Ty(), builder.getInt32Ty(), builder.getInt32Ty(), builder.getInt32Ty(), builder.getInt32Ty(), builder.getInt32Ty()}, false));
        auto *current = builder.CreateLoad(builder.getInt32Ty(), state);
        query = builder.CreateCall(helper, {owner->getArg(1), builder.getInt32(7), builder.getInt32(11), builder.getInt32(13),
            builder.getInt32(101), builder.getInt32(17), current}); query->setDoesNotThrow();
        query->setMetadata("pyobf.contribution.query", llvm::MDNode::get(context, llvm::ConstantAsMetadata::get(builder.getInt32(101))));
        auto *gate_branch = builder.CreateBr(start);
        gate_branch->setMetadata("pyobf.contribution.site", query->getMetadata("pyobf.contribution.query"));
        owner->addFnAttr("pyobf.contribution.count", "1");
        builder.SetInsertPoint(start); builder.CreateCondBr(owner->getArg(0), a, b);
        builder.SetInsertPoint(a); auto *invoke_a = builder.CreateInvoke(target, normal_a, pad, {});
        builder.SetInsertPoint(b); auto *invoke_b = builder.CreateInvoke(target, normal_b, pad, {});
        builder.SetInsertPoint(normal_a); builder.CreateBr(returned);
        builder.SetInsertPoint(normal_b); builder.CreateBr(returned);
        builder.SetInsertPoint(returned); builder.CreateRetVoid();
        builder.SetInsertPoint(pad); auto *exception = builder.CreateLandingPad(exception_type, 0); exception->setCleanup(true);
        builder.CreateStore(exception, saved); builder.CreateBr(cleanup);
        builder.SetInsertPoint(cleanup); builder.CreateResume(builder.CreateLoad(exception_type, saved));
        eh.invokes = {{invoke_a, returned, pad, normal_a}, {invoke_b, returned, pad, normal_b}};
        eh.pads = {{exception, pad, cleanup, true, {}}}; eh.boundaries = {normal_a, normal_b, pad};
        std::vector<llvm::BasicBlock *> bodies{gate, start, a, b, returned, cleanup};
        layout = build_state_layout(*owner, bodies, seed);
        auto input = std::make_shared<ContributionPrivate>();
        input->routing = 7; input->domain = 11; input->source = 17;
        input->words = {1, 2, 3, 4, 5, 6, 7, 8}; input->owners[owner->getName().str()] = 13;
        recipe.contribution = input; recipe.seeds["runtime-contribution"] = seed;
        if (grouped) {
            input->schema = 2;
            auto a = owned_contribution_source("alpha", 17, "bootstrap");
            auto b = owned_contribution_source("beta", 29, "bootstrap");
            auto c = owned_contribution_source("gamma", 41, "bootstrap");
            SiteBindingSpec binding;
            binding.owner = owner->getName().str(); binding.site = "101"; binding.sources = {a.id, b.id, c.id};
            binding.mixing_domain = "test-group"; binding.readiness = 4; binding.groups.push_back({"bootstrap", 3, false});
            const auto resolution = resolve_contribution_contract({owned_contribution_provider()}, {a, b, c}, {binding});
            if (!resolution.valid()) llvm::report_fatal_error(llvm::StringRef(resolution.failure));
            input->groups[binding.owner].defaults = {resolution.sites.front(), 77};
            query->setMetadata("pyobf.contribution.source", llvm::MDNode::get(context, llvm::ConstantAsMetadata::get(builder.getInt32(0))));
            builder.SetInsertPoint(gate_branch);
            for (unsigned index = 1; index != 3; ++index) {
                auto *source = builder.CreateCall(helper, {owner->getArg(1), builder.getInt32(7), builder.getInt32(11), builder.getInt32(13),
                    builder.getInt32(101), builder.getInt32(17 + 12 * index), query->getArgOperand(6)});
                source->setDoesNotThrow();
                source->setMetadata("pyobf.contribution.source", llvm::MDNode::get(context, llvm::ConstantAsMetadata::get(builder.getInt32(index))));
            }
            owner->addFnAttr("pyobf.contribution.grouped"); owner->addFnAttr("pyobf.contribution.queries", "3");
        }
        TransitionLayerPlans layer_plans;
        if (composition != 0) {
            for (auto *body : bodies) if (llvm::isa<llvm::BranchInst>(body->getTerminator())) {
                TransitionLayerDescription description{layout.states[body], layout.transition_salt, "", {}};
                unsigned index = 0;
                for (const auto &model : registered_transition_models()) {
                    if (composition & (1u << index)) description.models.push_back({&model, seed + index,
                        llvm::StringRef(model.name) == "reachable-junk" ? 2u : 0u});
                    ++index;
                }
                layer_plans.emplace(body, std::move(description));
            }
            layers = std::make_unique<TransitionLayers>(*owner, state, layout.transition_salt, layer_plans);
        }
        contribution = std::make_unique<ContributionGateSeal>(*owner, layout, recipe, layers.get());
        if (inconsistent_plan) gate_branch->setSuccessor(0, b);
        flow = std::make_unique<HybridFlowSeal>(*owner, eh, layout, state, dispatch);
        gate_branch->setSuccessor(0, start);
        if (const auto reason = bind_hybrid_eh(eh, *owner, layout, state, dispatch); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(reason));
        for (auto *body : bodies) {
            auto *branch = llvm::dyn_cast<llvm::BranchInst>(body->getTerminator());
            if (branch == nullptr) continue;
            builder.SetInsertPoint(branch);
            auto *read = builder.CreateLoad(builder.getInt32Ty(), state);
            const auto encoded = [&](unsigned index) { return builder.getInt32(encode_delta(layout.states[body],
                layout.states[branch->getSuccessor(index)], layout.transition_salt)); };
            llvm::Value *choice = branch->isConditional() ? builder.CreateSelect(branch->getCondition(), encoded(0), encoded(1)) : encoded(0);
            if (body == gate) choice = bind_contribution_transition(builder, choice, state, layout.states[body], seed, recipe);
            if (composition != 0) for (const auto &spec : layer_plans.at(body).models) {
                ResolvedRecipe configured; configured.junk_rounds = spec.rounds;
                choice = spec.model->emit(builder, choice, state, layout.states[body], spec.seed, configured);
            }
            auto *store = builder.CreateStore(builder.CreateAdd(read, decode_delta(builder, read, choice, layout.transition_salt)), state);
            if (composition != 0) store->setMetadata("pyobf.transition.layers", describe_transition_layers(context, layer_plans.at(body)));
            if (body == gate) store->setMetadata("pyobf.contribution.transition",
                llvm::MDNode::get(context, llvm::ConstantAsMetadata::get(builder.getInt32(layout.transition_salt))));
            builder.CreateBr(dispatch); branch->eraseFromParent();
        }
        auto *old = entry->getTerminator(); builder.SetInsertPoint(old);
        builder.CreateStore(builder.getInt32(layout.states[gate]), state); builder.CreateBr(dispatch); old->eraseFromParent();
        builder.SetInsertPoint(dispatch); current = builder.CreateLoad(builder.getInt32Ty(), state);
        builder.CreateBr(build_dispatch_tree(*owner, current, layout.sorted_leaves, layout.random_state));
    }
    StateUpdate update(llvm::BasicBlock *body) {
        const auto value = match_state_update(*body, state, layout.transition_salt, dispatch);
        if (!value) llvm::report_fatal_error("binding fixture lost actual update");
        return *value;
    }
};
}
