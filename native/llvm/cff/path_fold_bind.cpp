#include "path_fold_sites.hpp"
#include "path_fold.hpp"
#include "path_fold/value.hpp"
#include "site_report.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace pyobfuscator::native::cff {

unsigned bind_path_fold_sites(llvm::BasicBlock &body, llvm::Value *state_slot,
                               std::uint32_t expected, std::uint32_t salt, SiteCoverage *coverage) {
    std::vector<FoldMarker> markers;
    for (auto &instruction : body) {
        auto marker = inspect_path_fold_marker(instruction);
        if (marker.call != nullptr && marker.reason.empty() &&
                (coverage == nullptr || coverage->needs_site("path-fold", instruction))) markers.push_back(std::move(marker));
    }
    unsigned count = 0;
    for (auto &marker : markers) {
        auto *call = marker.call;
        const auto id = instruction_provenance(*call);
        const auto local_salt = component_seed(salt, id, "path-fold-word-v1");
        const auto encoded = path_fold::encode_word(marker.word, expected, local_salt);
        auto *storage = call->getArgOperand(0);
        llvm::IRBuilder<> builder(call);
        auto *current = builder.CreateLoad(builder.getInt32Ty(), state_slot, "pyobf.fold.state");
        current->setVolatile(true);
        current->setMetadata("pyobf.path-fold.state", llvm::MDNode::get(body.getContext(), {
            llvm::MDString::get(body.getContext(), id)}));
        auto *word = emit_path_fold_word(builder, current, encoded, local_salt);
        const auto stores = marker.kind == FoldKind::initialize ? emit_path_fold_initialize(builder, storage, word) :
            emit_path_fold_advance(builder, storage, builder.getInt32(marker.tag), word);
        auto &context = body.getContext();
        unsigned input_lane = 0;
        for (auto *instruction = current->getNextNode(); instruction != call; instruction = instruction->getNextNode())
            if (auto *load = llvm::dyn_cast<llvm::LoadInst>(instruction))
                load->setMetadata("pyobf.path-fold.before", llvm::MDNode::get(context, {
                    llvm::MDString::get(context, id), llvm::ConstantAsMetadata::get(builder.getInt32(input_lane++))}));
        for (unsigned lane = 0; lane != stores.size(); ++lane) {
            stores[lane]->setMetadata("pyobf.path-fold.bound", llvm::MDNode::get(context, {
                llvm::MDString::get(context, id), llvm::ConstantAsMetadata::get(builder.getInt32(1)),
                llvm::ConstantAsMetadata::get(builder.getInt32(static_cast<unsigned>(marker.kind))),
                llvm::ConstantAsMetadata::get(builder.getInt32(lane)),
                llvm::ConstantAsMetadata::get(builder.getInt32(marker.tag)),
                llvm::ConstantAsMetadata::get(builder.getInt32(encoded)),
                llvm::ConstantAsMetadata::get(builder.getInt32(local_salt))}));
        }
        stores.back()->setMetadata("pyobf.cff.site", call->getMetadata("pyobf.cff.site"));
        if (coverage != nullptr) {
            coverage->applied("path-fold", *stores.back());
            coverage->record_type("path-fold", marker.kind == FoldKind::initialize ? "initialize32x8" : "advance32x8");
        }
        call->eraseFromParent();
        body.getParent()->addFnAttr("pyobf.path-fold.bound");
        ++count;
    }
    return count;
}

}  // namespace pyobfuscator::native::cff
