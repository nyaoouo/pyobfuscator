#include "call_frames.hpp"
#include "site_provenance.hpp"
#include "source_marker.hpp"

#include <algorithm>
#include <numeric>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

FrameLayout call_frame_layout(const llvm::CallBase &call, const ResolvedRecipe &recipe) {
    std::vector<llvm::Type *> fields{llvm::PointerType::getUnqual(call.getContext())};
    for (const auto &argument : call.args()) fields.push_back(argument->getType());
    const auto result = static_cast<unsigned>(fields.size());
    if (!call.getType()->isVoidTy()) fields.push_back(call.getType());
    unsigned padding = ~0u;
    if (recipe.enabled("call-preparation")) {
        const auto &data = call.getModule()->getDataLayout();
        std::uint64_t bytes = 1, alignment = 1;
        for (const auto *type : fields) {
            bytes = std::max(bytes, data.getTypeAllocSize(const_cast<llvm::Type *>(type)).getFixedValue());
            alignment = std::max(alignment, data.getABITypeAlign(const_cast<llvm::Type *>(type)).value());
        }
        padding = fields.size();
        fields.push_back(llvm::ArrayType::get(llvm::Type::getInt8Ty(call.getContext()), bytes + alignment));
    }
    std::vector<unsigned> order(fields.size()), indices(fields.size());
    std::iota(order.begin(), order.end(), 0);
    const auto component = call.getCalledFunction()->isDeclaration() ? "external-calls" : "call-frames";
    std::uint64_t random = component_seed(recipe.seeds.at(component), call.getFunction()->getName(),
        instruction_site_id(call, component, 0));
    for (unsigned index = order.size() - 1; index > 0; --index) {
        random = random * 6364136223846793005ull + 1442695040888963407ull;
        std::swap(order[index], order[(random >> 32) % (index + 1)]);
    }
    std::vector<llvm::Type *> shuffled;
    for (unsigned index = 0; index < order.size(); ++index) {
        indices[order[index]] = index;
        shuffled.push_back(fields[order[index]]);
    }
    FrameLayout layout{llvm::StructType::get(call.getContext(), shuffled), indices[0],
        call.getType()->isVoidTy() ? ~0u : indices[result], {}};
    for (unsigned index = 0; index < call.arg_size(); ++index) layout.arguments.push_back(indices[index + 1]);
    if (padding != ~0u) layout.padding = indices[padding];
    return layout;
}

std::string call_frame_reason(const llvm::CallBase &call, const ResolvedRecipe &recipe, bool external) {
    const auto *target = call.getCalledFunction();
    if (target == nullptr || target->isIntrinsic() || target->hasAvailableExternallyLinkage() ||
        target->isDeclaration() != external)
        return external ? "external frames require a direct external function declaration" :
                          "call frames require a direct emitted internal target";
    if (external && !target->hasExternalLinkage())
        return "external frames require a strong external declaration";
    if (target->getAddressSpace() != 0 || call.getFunctionType()->isVarArg() ||
        call.getFunctionType() != target->getFunctionType() || call.getCallingConv() != target->getCallingConv())
        return "call frames require an exact nonvariadic AS0 call ABI";
    if (call.isMustTailCall() || call.hasOperandBundles() || call.isInlineAsm() ||
        call.isConvergent() || call.cannotDuplicate() || call.cannotMerge() ||
        call.hasFnAttr(llvm::Attribute::ReturnsTwice))
        return "call frames retain musttail, bundles and special call-control semantics";
    for (const auto &block : *target) for (const auto &instruction : block)
        if (const auto *nested = llvm::dyn_cast<llvm::CallBase>(&instruction))
            if (const auto *function = nested->getCalledFunction(); function != nullptr &&
                (function->getName().starts_with("llvm.returnaddress") || function->getName().starts_with("llvm.frameaddress") ||
                 function->getName().starts_with("llvm.addressofreturnaddress")))
                return "call frames cannot preserve a target's physical caller-frame observation";
    for (unsigned index = 0; index < call.arg_size(); ++index)
        for (const auto kind : {llvm::Attribute::InAlloca, llvm::Attribute::Preallocated,
                               llvm::Attribute::SwiftError, llvm::Attribute::SwiftSelf, llvm::Attribute::Nest})
            if (call.paramHasAttr(index, kind) || target->hasParamAttribute(index, kind))
                return "call frames do not transport this special parameter ABI";
    const auto &module = *call.getModule();
    const auto &data = module.getDataLayout();
    if (module.getDataLayoutStr().empty() || (data.getPointerSizeInBits() != 32 && data.getPointerSizeInBits() != 64) ||
        data.getAllocaAddrSpace() != 0 || call.getFunction()->hasFnAttribute(llvm::Attribute::Naked))
        return "call frames need an explicit 32/64-bit AS0 stack layout";
    const auto supported = [&](llvm::Type *type) {
        return type->isSized() && type->isFirstClassType() && !type->isTokenTy() &&
            !type->isTargetExtTy() && !type->containsNonLocalTargetExtType() && !type->isScalableTy() &&
            !data.getTypeAllocSize(type).isScalable();
    };
    if (!call.getType()->isVoidTy() && !supported(call.getType())) return "call frame result has unsupported storage";
    for (const auto &argument : call.args())
        if (!supported(argument->getType())) return "call frame argument has unsupported storage";
    const auto layout = call_frame_layout(call, recipe);
    if (data.getTypeAllocSize(layout.type).getFixedValue() > recipe.max_frame_bytes)
        return "call frame exceeds max_frame_bytes";
    return {};
}

std::vector<InstructionSite> discover_frame_calls(llvm::Function &function, const ResolvedRecipe &recipe, bool external) {
    std::vector<InstructionSite> sites;
    if (function.hasFnAttribute("pyobf.archive.wrapper")) return sites;
    std::uint64_t bytes = 0;
    unsigned eligible = 0;
    for (auto &block : function) for (auto &instruction : block) {
        if (const auto info = read_frame_metadata(instruction.getMetadata("pyobf.frame.storage"))) {
            ++eligible;
            bytes += function.getParent()->getDataLayout().getTypeAllocSize(info->layout.type).getFixedValue();
        }
        auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        const auto *target = call == nullptr ? nullptr : call->getCalledFunction();
        if (target == nullptr || target->isIntrinsic() || source_marker_name(target->getName()) ||
            call->getMetadata("pyobf.archive.gate") != nullptr || call->getMetadata("pyobf.frame.invoke") != nullptr) continue;
        const bool imported = target->isDeclaration();
        if (imported != external && !recipe.enabled(imported ? "external-calls" : "call-frames")) continue;
        auto reason = call_frame_reason(*call, recipe, imported);
        if (reason.empty()) {
            ++eligible;
            bytes += function.getParent()->getDataLayout().getTypeAllocSize(call_frame_layout(*call, recipe).type).getFixedValue();
        }
        if (imported == external) sites.push_back({call, 0, std::move(reason)});
    }
    for (auto &site : sites) if (site.reason.empty()) {
        if (eligible > recipe.max_frame_sites) site.reason = "call frames exceed max_frame_sites";
        if (bytes > recipe.max_frame_total_bytes) site.reason = "call frames exceed max_frame_total_bytes";
    }
    return sites;
}

std::vector<InstructionSite> discover_call_frames(llvm::Function &function, const ResolvedRecipe &recipe) {
    return discover_frame_calls(function, recipe, false);
}

}  // namespace pyobfuscator::native::cff
