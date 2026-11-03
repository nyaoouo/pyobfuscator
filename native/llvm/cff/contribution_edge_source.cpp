#include "contribution_edges.hpp"
#include "contribution_gate.hpp"
#include "contribution_private.hpp"

#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"

#include <set>

namespace pyobfuscator::native::cff {
namespace {
llvm::Value *origin(llvm::Value *value, llvm::Function &function, llvm::DominatorTree *dominators) {
    if (llvm::isa<llvm::Argument, llvm::GlobalVariable>(value)) return value;
    auto *read = llvm::dyn_cast<llvm::LoadInst>(value);
    auto *slot = read == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(read->getPointerOperand());
    if (read == nullptr || !read->isSimple() || slot == nullptr || slot->getParent() != &function.getEntryBlock() ||
            !slot->getAllocatedType()->isPointerTy()) return nullptr;
    llvm::StoreInst *initial = nullptr;
    for (auto *user : slot->users()) {
        if (auto *load = llvm::dyn_cast<llvm::LoadInst>(user); load != nullptr && load->getPointerOperand() == slot && load->isSimple()) continue;
        if (auto *write = llvm::dyn_cast<llvm::StoreInst>(user); write != nullptr && write->getPointerOperand() == slot && write->isSimple()) {
            if (initial != nullptr) return nullptr;
            initial = write; continue;
        }
        if (auto *intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(user); intrinsic != nullptr &&
                (intrinsic->getIntrinsicID() == llvm::Intrinsic::lifetime_start || intrinsic->getIntrinsicID() == llvm::Intrinsic::lifetime_end)) continue;
        return nullptr;
    }
    if (initial == nullptr || (dominators != nullptr && !dominators->dominates(initial, read))) return nullptr;
    auto *source = initial->getValueOperand();
    return llvm::isa<llvm::Argument, llvm::GlobalVariable>(source) ? source : nullptr;
}
}
llvm::Value *contribution_edge_reference_origin(llvm::Value *value, llvm::Function &function) {
    // CFF error-state routes need not pass the original entry spill. Its sole
    // immutable write was checked for dominance before the original CFG changed.
    return origin(value, function, nullptr);
}
llvm::Value *canonical_contribution_source(llvm::Function &function, const ResolvedRecipe &recipe,
    std::vector<ContributionEdgeAnchor> &anchors, bool &multiple, std::string &failure) {
    llvm::DominatorTree dominators(function);
    llvm::Value *source = nullptr;
    std::set<std::uint32_t> labels;
    const auto points = discover_contribution_sites(function, recipe);
    if (recipe.contribution && recipe.contribution->schema == 4 &&
            recipe.contribution_options.selection == ContributionSelection::original_edges) {
        if (!points.empty()) { failure = "source-mixed automatic edges cannot use explicit markers"; return nullptr; }
        if (function.arg_size() < 2 || !function.getArg(0)->getType()->isPointerTy() ||
                !function.getArg(1)->getType()->isPointerTy() ||
                function.getArg(0)->getType()->getPointerAddressSpace() != 0 ||
                function.getArg(1)->getType()->getPointerAddressSpace() != 0) {
            failure = "source-mixed automatic edges need distinct owned/measured pointer arguments"; return nullptr;
        }
        return function.getArg(0);
    }
    if (points.empty()) { failure = "automatic contributions require a source marker"; return nullptr; }
    for (const auto &point : points) {
        if (!point.reason.empty()) { failure = point.reason; return nullptr; }
        auto *marker = llvm::cast<llvm::CallInst>(point.instruction);
        auto *candidate = origin(marker->getArgOperand(0), function, &dominators);
        const auto label = static_cast<std::uint32_t>(llvm::cast<llvm::ConstantInt>(marker->getArgOperand(1))->getZExtValue());
        if (candidate == nullptr || !labels.insert(label).second) {
            failure = candidate == nullptr ? "automatic contributions require one canonical argument/global lease reference held through return" :
                "automatic contribution anchor site is duplicated";
            return nullptr;
        }
        anchors.push_back({label, marker, marker->getArgOperand(0), candidate});
        if (source != nullptr && candidate != source) multiple = true;
        else source = candidate;
    }
    return multiple ? nullptr : source;
}
}
