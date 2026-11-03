#include "contribution_edges.hpp"
#include "contribution_private.hpp"
#include "cfg_origin.hpp"
#include "region_scope.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
unsigned ContributionEdgePlan::instrument(llvm::Function &function, CfgOrigins &origins) {
    if (&function != owner_ || !failure_.empty() || (lease_ == nullptr && !multiple_scopes_) ||
            (source_mixed_ && measured_ == nullptr) || materialized_)
        llvm::report_fatal_error(llvm::StringRef(failure_.empty() ? "automatic contribution owner/source changed" : failure_));
    if (const auto reason = plan_aliases(); !reason.empty()) llvm::report_fatal_error(llvm::StringRef(reason));
    if (physical_selected() + explicit_points_ > maximum_queries_)
        llvm::report_fatal_error("automatic and explicit queries exceed max_contribution_sites");
    if (selected_ == 0) { materialized_ = true; return 0; }
    if (multiple_scopes_) function.addFnAttr("pyobf.contribution.multiscope", "v1");
    auto &context = function.getContext();
    auto *pointer = llvm::PointerType::getUnqual(context);
    auto *word = llvm::Type::getInt32Ty(context);
    auto *type = source_mixed_ ? llvm::FunctionType::get(llvm::Type::getVoidTy(context),
        {pointer, pointer, word}, false) : llvm::FunctionType::get(llvm::Type::getVoidTy(context),
        {pointer, word}, false);
    auto marker = function.getParent()->getOrInsertFunction(source_mixed_ ?
        "pyobf_native_mixed_contribution_site_v1" :
        private_ && private_->provider == "measured-scope-v1" ?
        "pyobf_native_measured_contribution_site_v1" : "pyobf_native_contribution_site_v1", type);
    if (marker.getFunctionType() != llvm::cast<llvm::Function>(marker.getCallee())->getFunctionType())
        llvm::report_fatal_error("automatic contribution marker ABI changed");
    for (unsigned i = 0; i != edges_.size(); ++i) {
        auto &edge = edges_[i];
        if (!edge.selected || canonical_[i] != i) continue;
        auto *term = insertion_source(edge);
        auto *target = llvm::cast<llvm::BasicBlock>(edge.target);
        auto *source = term->getParent();
        auto *gateway = llvm::BasicBlock::Create(context, "pyobf.contribution.edge", &function);
        for (auto &phi : target->phis()) {
            const auto incoming = phi.getBasicBlockIndex(source);
            if (incoming < 0) llvm::report_fatal_error("automatic edge has no corresponding PHI incoming value");
            phi.setIncomingBlock(incoming, gateway);
        }
        term->setSuccessor(edge.successor, gateway);
        llvm::IRBuilder<> builder(gateway);
        auto *reference = multiple_scopes_ ? static_cast<llvm::Value *>(edge.reference) : static_cast<llvm::Value *>(lease_);
        if (reference == nullptr) llvm::report_fatal_error("selected Scope edge lost its frozen reference");
        auto *call = source_mixed_ ? builder.CreateCall(marker,
            {reference, static_cast<llvm::Value *>(measured_), builder.getInt32(edge.label)}) :
            builder.CreateCall(marker, {reference, builder.getInt32(edge.label)});
        call->setDoesNotThrow();
        if (multiple_scopes_) {
            llvm::SmallVector<llvm::Metadata *, 3> descriptor{
                llvm::ConstantAsMetadata::get(builder.getInt32(edge.reference_site))};
            if (auto *argument = llvm::dyn_cast<llvm::Argument>(reference)) {
                descriptor.push_back(llvm::ConstantAsMetadata::get(builder.getInt32(1)));
                descriptor.push_back(llvm::ConstantAsMetadata::get(builder.getInt32(argument->getArgNo())));
            } else if (auto *global = llvm::dyn_cast<llvm::GlobalVariable>(reference)) {
                descriptor.push_back(llvm::ConstantAsMetadata::get(builder.getInt32(2)));
                descriptor.push_back(llvm::MDString::get(context, global->getName()));
            } else llvm::report_fatal_error("selected Scope edge has no canonical argument/global reference");
            call->setMetadata("pyobf.contribution.edge.anchor", llvm::MDNode::get(context, descriptor));
        }
        call->setMetadata("pyobf.cff.site", llvm::MDNode::get(context, llvm::MDString::get(context, "contribution-edge." + edge.identity)));
        builder.CreateBr(target);
        origins.set(*gateway, BlockRole::routing);
        edge.gateway = gateway;
        for (auto &invoke : invokes_) if (invoke.source == edge.terminator) invoke.normal = gateway;
        if (region_scope_) region_scope_->adopt(*gateway);
    }
    for (unsigned i = 0; i != edges_.size(); ++i)
        if (edges_[i].selected) edges_[i].gateway = edges_[canonical_[i]].gateway;
    materialized_ = true;
    return selected_;
}
}
