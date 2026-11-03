#include "call_preparation.hpp"
#include "external_calls.hpp"
#include "site_report.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {

unsigned steps(const FrameLayout &layout, const llvm::DataLayout &data) {
    unsigned count = 1;
    for (unsigned index = 0; index < layout.type->getNumElements(); ++index)
        if (index != layout.padding && data.getTypeAllocSize(layout.type->getElementType(index)).getFixedValue()) ++count;
    return count;
}

}  // namespace

std::vector<InstructionSite> discover_call_preparation(llvm::Function &function, const ResolvedRecipe &recipe) {
    std::vector<InstructionSite> sites;
    std::uint64_t count = 0;
    if (const auto *tag = function.getMetadata("pyobf.frame.helper")) {
        const auto info = read_frame_metadata(tag);
        for (auto &block : function) for (auto &instruction : block)
            if (instruction.getMetadata("pyobf.frame.inner") == tag) {
                sites.push_back({&instruction, 0, !info || info->layout.padding == ~0u ?
                    "call preparation requires a reserved owned frame layout" : ""});
                if (info) count += steps(info->layout, function.getParent()->getDataLayout());
            }
    } else {
        if (recipe.enabled("call-frames")) sites = discover_call_frames(function, recipe);
        if (recipe.enabled("external-calls")) {
            auto external = discover_external_calls(function, recipe);
            sites.insert(sites.end(), external.begin(), external.end());
        }
        for (const auto &site : sites) if (site.reason.empty())
            count += steps(call_frame_layout(*llvm::cast<llvm::CallBase>(site.instruction), recipe),
                           function.getParent()->getDataLayout());
    }
    if (count > recipe.max_preparation_steps)
        for (auto &site : sites) if (site.reason.empty()) site.reason = "call preparation exceeds max_preparation_steps";
    return sites;
}

unsigned normalize_call_preparation(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    auto *inventory = function.getParent()->getNamedMetadata("pyobf.prep.inventory");
    if (inventory == nullptr) return 0;
    unsigned addresses = 0, empty = 0, anchors = 0;
    for (const auto *record : inventory->operands()) {
        const auto *descriptor = record->getNumOperands() == 3 ? llvm::dyn_cast<llvm::MDNode>(record->getOperand(0)) : nullptr;
        const auto info = read_frame_metadata(descriptor);
        const auto *owner = record->getNumOperands() == 3 ? llvm::dyn_cast<llvm::ValueAsMetadata>(record->getOperand(1)) : nullptr;
        if (!info || owner == nullptr || info->layout.padding == ~0u)
            llvm::report_fatal_error("native call preparation has an invalid planned frame");
        const bool helper = info->helper == &function;
        if (!helper && owner->getValue() != &function) continue;
        llvm::Value *root = helper ? static_cast<llvm::Value *>(function.getArg(0)) : nullptr;
        if (!helper) for (auto &block : function) for (auto &instruction : block)
            if (instruction.getMetadata("pyobf.frame.storage") == descriptor) {
                if (root != nullptr) llvm::report_fatal_error("native preparation frame has multiple owners");
                root = &instruction;
            }
        if (root == nullptr) llvm::report_fatal_error("native call preparation lost its frame storage");
        for (auto &block : function) for (auto &instruction : block) {
            if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction);
                gep != nullptr && gep->getPointerOperand() == root && gep->getSourceElementType() == info->layout.type) {
                const auto *index = gep->getNumIndices() == 2 ? llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(2)) : nullptr;
                if (index == nullptr || index->getValue().uge(info->layout.type->getNumElements()))
                    llvm::report_fatal_error("native preparation field is not a bounded struct access");
                const auto field = static_cast<unsigned>(index->getZExtValue());
                if (!function.getParent()->getDataLayout().getTypeAllocSize(info->layout.type->getElementType(field)).getFixedValue()) {
                    ++empty; continue;
                }
                const auto salt = component_seed(recipe.seeds.at("call-preparation"), function.getName(),
                    instruction_site_id(instruction, "call-preparation", field) + "." + std::to_string(addresses));
                llvm::IRBuilder<> builder(function.getContext());
                gep->setMetadata("pyobf.prep.pending", llvm::MDNode::get(function.getContext(), {
                    const_cast<llvm::MDNode *>(descriptor), llvm::ConstantAsMetadata::get(builder.getInt32(field)),
                    llvm::ConstantAsMetadata::get(builder.getInt32(salt))}));
                ++addresses;
            }
            const auto *tag = instruction.getMetadata(helper ? "pyobf.frame.inner" : "pyobf.frame.invoke");
            if (tag == descriptor) {
                instruction.setMetadata("pyobf.prep.anchor", llvm::MDNode::get(function.getContext(), {
                    const_cast<llvm::MDNode *>(descriptor), llvm::MDString::get(function.getContext(), helper ? "invoker" : "caller")}));
                ++anchors;
            }
        }
    }
    coverage.preparation_metric("call-preparation", "field_addresses", addresses);
    coverage.preparation_metric("call-preparation", "empty_fields", empty);
    coverage.preparation_metric("call-preparation", "logical_sites", anchors);
    return addresses;
}

}  // namespace pyobfuscator::native::cff
