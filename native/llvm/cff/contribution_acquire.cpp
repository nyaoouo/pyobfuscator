#include "contribution_gate.hpp"
#include "contribution_private.hpp"
#include "contribution_contract.hpp"
#include "contribution_groups.hpp"
#include "contribution_query.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
unsigned prepare_contribution_sites(llvm::Function &function, llvm::Value *state,
    const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    const auto sites = discover_contribution_sites(function, recipe);
    if (sites.empty()) return 0;
    if (!recipe.contribution || !recipe.contribution->owners.count(function.getName().str()))
        llvm::report_fatal_error("contribution needs an independent private owner reference");
    if (recipe.contribution->schema >= 2) return prepare_contribution_group_sites(function, state, recipe, coverage);
    ProviderCapabilities provider;
    provider.id = "owned-context-v1"; provider.version = 1;
    provider.classes = {SourceClass::authenticated_material}; provider.widths = {32};
    provider.references = {ReferenceSemantics::authenticated_context};
    provider.policies = {ObservationPolicy::per_use}; provider.encodings = {{"le-u32", 1}};
    provider.earliest_readiness = 4; provider.available = true;
    SourceSpec source;
    source.id = "bootstrap-material"; source.source_class = SourceClass::authenticated_material;
    source.bit_width = 32; source.reference = ReferenceSemantics::authenticated_context;
    source.earliest_readiness = 4; source.provider = provider.id; source.provider_version = 1;
    source.encoding = "le-u32"; source.word_label = recipe.contribution->source;
    source.sharing = ObservationSharing::context_material; source.group = "bootstrap";
    if (recipe.contribution->provider == "measured-scope-v1") {
        provider.id = "measured-scope-v1";
        provider.classes = {SourceClass::referenced_evidence};
        provider.references = {ReferenceSemantics::independent_build};
        provider.independent_observations = true;
        source.id = "measured-material"; source.provider = provider.id;
        source.source_class = SourceClass::referenced_evidence;
        source.reference = ReferenceSemantics::independent_build;
        source.sharing = ObservationSharing::owner_independent;
        function.addFnAttr("pyobf.contribution.scope", "v1");
    }
    std::vector<SiteBindingSpec> bindings;
    for (unsigned index = 0; index != sites.size(); ++index) {
        SiteBindingSpec binding;
        binding.site = "explicit:" + std::to_string(index); binding.owner = function.getName().str();
        binding.sources = {source.id}; binding.mixing_domain = "owned-context-v1"; binding.readiness = 4;
        binding.groups.push_back({"bootstrap", 1, false}); bindings.push_back(std::move(binding));
    }
    if (const auto resolved = resolve_contribution_contract({provider}, {source}, bindings); !resolved.valid())
        llvm::report_fatal_error(llvm::StringRef(resolved.failure));
    auto &context = function.getContext();
    auto *word = llvm::Type::getInt32Ty(context);
    auto *type = llvm::FunctionType::get(word, {llvm::PointerType::getUnqual(context), word, word, word, word, word, word}, false);
    auto helper = function.getParent()->getOrInsertFunction(contribution_query_name(function), type);
    const auto *target = llvm::dyn_cast<llvm::Function>(helper.getCallee());
    if (target == nullptr || target->getFunctionType() != type || target->getCallingConv() != llvm::CallingConv::C ||
            target->hasDLLImportStorageClass()) llvm::report_fatal_error("contribution query helper has a conflicting ABI");
    unsigned applied = 0;
    for (const auto &site : sites) {
        if (!site.reason.empty()) llvm::report_fatal_error(llvm::StringRef(site.reason));
        auto *marker = llvm::cast<llvm::CallInst>(site.instruction);
        auto *branch = marker->getParent()->getTerminator();
        if (!llvm::isa<llvm::BranchInst>(branch))
            llvm::report_fatal_error("contribution routing gateway lost its normal branch");
        llvm::IRBuilder<> builder(marker);
        auto *current = builder.CreateLoad(word, state, "pyobf.contribution.current");
        const auto &input = *recipe.contribution;
        auto *query = builder.CreateCall(helper, {marker->getArgOperand(0), builder.getInt32(input.routing),
            builder.getInt32(input.domain), builder.getInt32(input.owners.at(function.getName().str())),
            marker->getArgOperand(1), builder.getInt32(input.source), current}, "pyobf.contribution.word");
        query->setDoesNotThrow();
        query->setMetadata("pyobf.contribution.query", llvm::MDNode::get(context,
            {llvm::ConstantAsMetadata::get(llvm::cast<llvm::ConstantInt>(marker->getArgOperand(1)))}));
        branch->setMetadata("pyobf.contribution.site", query->getMetadata("pyobf.contribution.query"));
        // Credit the original point once, when its actual transition is bound at A5.
        branch->setMetadata("pyobf.cff.site", marker->getMetadata("pyobf.cff.site"));
        branch->setDebugLoc(marker->getDebugLoc());
        marker->eraseFromParent(); ++applied;
    }
    llvm::cast<llvm::Instruction>(state)->setMetadata("pyobf.contribution.root", llvm::MDNode::get(context, {}));
    function.addFnAttr("pyobf.contribution.count", std::to_string(applied));
    return applied;
}
}
