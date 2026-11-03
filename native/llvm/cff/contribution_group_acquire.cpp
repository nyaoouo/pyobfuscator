#include "contribution_groups.hpp"
#include "contribution_gate.hpp"
#include "contribution_private.hpp"
#include "contribution_reference_origin.hpp"
#include "contribution_edges.hpp"
#include "contribution_query.hpp"
#include "site_report.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
unsigned prepare_contribution_group_sites(llvm::Function &function, llvm::Value *state,
    const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    const auto sites = discover_contribution_sites(function, recipe);
    std::vector<std::uint32_t> labels;
    for (const auto &site : sites) {
        if (!site.reason.empty()) llvm::report_fatal_error(llvm::StringRef(site.reason));
        labels.push_back(llvm::cast<llvm::ConstantInt>(llvm::cast<llvm::CallInst>(site.instruction)->getArgOperand(
            recipe.contribution->schema == 4 ? 2 : 1))->getZExtValue());
    }
    const auto &input = *recipe.contribution;
    if (input.schema == 4 && sites.size() == 2 &&
        (recipe.strategy != "relative-tree" || recipe.coverage != "whole" || recipe.region_scope))
        llvm::report_fatal_error("source-mixed two-site requires whole relative-tree scope");
    const auto owner = function.getName().str();
    if (!coverage.contribution_edges) {
        const auto found = input.groups.find(owner);
        if (found != input.groups.end()) for (const auto &[site, rule] : found->second.sites)
            if (rule.reference_site) llvm::report_fatal_error("reference_site requires original-edge selection");
    }
    const auto aliases = coverage.contribution_edges ? coverage.contribution_edges->aliased_point_labels() : std::vector<std::uint32_t>{};
    if (const auto reason = validate_contribution_group_sites(input, owner, labels, recipe.max_contribution_sites, aliases); !reason.empty())
        llvm::report_fatal_error(llvm::StringRef(reason));
    auto &context = function.getContext();
    auto *word = llvm::Type::getInt32Ty(context);
    auto *pointer = llvm::PointerType::getUnqual(context);
    auto *legacy_type = llvm::FunctionType::get(word, {pointer, word, word, word, word, word, word}, false);
    auto *joint_type = llvm::FunctionType::get(word, {pointer, word, word, word, word, word, word, pointer}, false);
    const auto helper_for = [&](llvm::StringRef provider) {
        auto *type = input.schema == 4 ? joint_type : legacy_type;
        auto helper = function.getParent()->getOrInsertFunction(contribution_group_query_name(provider, input.schema), type);
        const auto *target = llvm::dyn_cast<llvm::Function>(helper.getCallee());
        if (target == nullptr || target->getFunctionType() != type || target->getCallingConv() != llvm::CallingConv::C ||
                target->hasDLLImportStorageClass()) llvm::report_fatal_error("contribution query helper has a conflicting ABI");
        return helper;
    };
    unsigned queries = 0;
    for (unsigned index = 0; index != sites.size(); ++index) {
        auto *marker = llvm::cast<llvm::CallInst>(sites[index].instruction);
        auto *branch = marker->getParent()->getTerminator();
        if (!llvm::isa<llvm::BranchInst>(branch)) llvm::report_fatal_error("contribution group lost its normal routing branch");
        llvm::IRBuilder<> builder(marker);
        auto *current = builder.CreateLoad(word, state, "pyobf.contribution.current");
        const auto &group = contribution_source_group(input, owner, labels[index]);
        auto *site_value = marker->getArgOperand(input.schema == 4 ? 2 : 1);
        unsigned ordinal = 0;
        for (const auto &source : group.binding.sources) {
            const auto measured = source.spec.provider == "measured-scope-v1";
            auto helper = helper_for(source.spec.provider);
            auto *reference = marker->getArgOperand(input.schema == 4 && measured ? 1 : 0);
            auto *peer = input.schema == 4 ? marker->getArgOperand(measured ? 0 : 1) : nullptr;
            std::optional<unsigned> origin, peer_origin;
            if (input.schema == 4) {
                origin = contribution_reference_argument(reference, function);
                peer_origin = contribution_reference_argument(peer, function);
                if (!origin || !peer_origin) llvm::report_fatal_error("source-mixed references lost their canonical arguments");
                // The second selected site may not be dominated by the first site's
                // original entry spill after flattening. Its frozen arguments are.
                if (sites.size() == 2) {
                    reference = function.getArg(*origin);
                    peer = function.getArg(*peer_origin);
                }
            }
            llvm::SmallVector<llvm::Value *, 8> arguments{reference, builder.getInt32(input.routing),
                builder.getInt32(input.domain), builder.getInt32(input.owners.at(owner)), site_value,
                builder.getInt32(source.spec.word_label), current};
            if (input.schema == 4) arguments.push_back(peer);
            auto *query = builder.CreateCall(helper, arguments, "pyobf.contribution.word");
            query->setDoesNotThrow();
            llvm::SmallVector<llvm::Metadata *, 2> source_fields{
                llvm::ConstantAsMetadata::get(builder.getInt32(ordinal))};
            if (input.schema == 4) {
                source_fields.push_back(llvm::ConstantAsMetadata::get(builder.getInt32(*origin)));
                source_fields.push_back(llvm::ConstantAsMetadata::get(builder.getInt32(*peer_origin)));
            }
            query->setMetadata("pyobf.contribution.source", llvm::MDNode::get(context, source_fields));
            if (ordinal++ == 0) {
                query->setMetadata("pyobf.contribution.query", llvm::MDNode::get(context,
                    {llvm::ConstantAsMetadata::get(builder.getInt32(labels[index]))}));
                if (auto *anchor = marker->getMetadata("pyobf.contribution.edge.anchor"))
                    query->setMetadata("pyobf.contribution.edge.anchor", anchor);
            }
            ++queries;
        }
        branch->setMetadata("pyobf.contribution.site", llvm::MDNode::get(context,
            {llvm::ConstantAsMetadata::get(builder.getInt32(labels[index]))}));
        branch->setMetadata("pyobf.cff.site", marker->getMetadata("pyobf.cff.site"));
        branch->setDebugLoc(marker->getDebugLoc()); marker->eraseFromParent();
    }
    llvm::cast<llvm::Instruction>(state)->setMetadata("pyobf.contribution.root", llvm::MDNode::get(context, {}));
    function.addFnAttr("pyobf.contribution.count", std::to_string(sites.size()));
    function.addFnAttr("pyobf.contribution.queries", std::to_string(queries));
    function.addFnAttr("pyobf.contribution.grouped");
    if (input.schema == 4) function.addFnAttr("pyobf.contribution.scope", "source-mixed-v1");
    else if (input.schema == 3) function.addFnAttr("pyobf.contribution.scope", "mixed-v1");
    else if (input.provider == "measured-scope-v1") function.addFnAttr("pyobf.contribution.scope", "v1");
    return sites.size();
}
}
