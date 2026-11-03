#include "call_frames.hpp"
#include "site_report.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

unsigned normalize_frame_component(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage,
                                      llvm::StringRef component) {
    const auto sites = find_component(component)->discover(function, recipe);
    unsigned count = 0, total_bytes = 0, exclusions = 0;
    for (const auto &block : function) for (const auto &instruction : block)
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction); call != nullptr) {
            const auto *target = call->getCalledFunction();
            exclusions += function.hasFnAttribute("pyobf.archive.wrapper") || target == nullptr ||
                target->isIntrinsic() || target->isDeclaration() != (component == "external-calls") ||
                call->getMetadata("pyobf.archive.gate") != nullptr;
        }
    for (const auto &site : sites) {
        if (!site.reason.empty()) continue;
        auto *call = llvm::cast<llvm::CallBase>(site.instruction);
        auto *descriptor = call->getMetadata("pyobf.frame.plan");
        const auto info = read_frame_metadata(descriptor);
        if (!info || info->target != call->getCalledFunction() ||
            info->helper->getMetadata("pyobf.frame.helper") != descriptor)
            llvm::report_fatal_error("native call frame was not planned before definition sealing");
        llvm::IRBuilder<> allocation(&*function.getEntryBlock().getFirstInsertionPt());
        auto *frame = allocation.CreateAlloca(info->layout.type, nullptr, "pyobf.call.frame");
        frame->setAlignment(function.getParent()->getDataLayout().getABITypeAlign(info->layout.type));
        frame->setMetadata("pyobf.frame.storage", descriptor);
        llvm::IRBuilder<> builder(call);
        builder.SetCurrentDebugLocation(call->getDebugLoc());
        const auto write = [&](llvm::Value *value, unsigned field) {
            auto *address = builder.CreateStructGEP(info->layout.type, frame, field, "pyobf.frame.slot");
            return builder.CreateStore(value, address);
        };
        auto *target_store = write(call->getCalledOperand(), info->layout.target);
        target_store->setMetadata("pyobf.frame.target", descriptor);
        coverage.relocate_use("split-blocks", *call, 0, *target_store, 0);
        coverage.relocate_use("reference-routes", *call, call->getCalledOperandUse().getOperandNo(), *target_store, 0);
        coverage.relocate_use("import-routes", *call, call->getCalledOperandUse().getOperandNo(), *target_store, 0);
        for (unsigned index = 0; index < call->arg_size(); ++index) {
            auto *store = write(call->getArgOperand(index), info->layout.arguments[index]);
            store->setMetadata("pyobf.frame.argument", llvm::MDNode::get(function.getContext(), {
                descriptor, llvm::ConstantAsMetadata::get(builder.getInt32(index))}));
            coverage.relocate_use("reference-routes", *call, index, *store, 0);
            coverage.relocate_use("import-routes", *call, index, *store, 0);
            coverage.relocate_use("integer-literals", *call, index, *store, 0);
        }
        auto *invoke = emit_frame_dispatch(*call, *info->helper, frame, builder, coverage);
        invoke->setMetadata("pyobf.frame.invoke", descriptor);
        coverage.relocate_use("cfg", *call, 0, *invoke, 0);
        coverage.relocate_use(component, *call, 0, *invoke, 0);
        coverage.relocate_use("call-preparation", *call, 0, *invoke, 0);
        coverage.applied(component, *invoke);
        coverage.record_type(component, call->getType()->isVoidTy() ? "void" : "value");
        if (!call->getType()->isVoidTy()) {
            auto *address = builder.CreateStructGEP(info->layout.type, frame, info->layout.result, "pyobf.frame.result.slot");
            auto *result = builder.CreateLoad(call->getType(), address, "pyobf.frame.result");
            result->setMetadata("pyobf.frame.result", descriptor);
            call->replaceAllUsesWith(result);
        }
        total_bytes += static_cast<unsigned>(function.getParent()->getDataLayout().getTypeAllocSize(info->layout.type).getFixedValue());
        call->eraseFromParent();
        ++count;
    }
    if (count) {
        function.removeFnAttr(llvm::Attribute::Memory);
        function.removeFnAttr(llvm::Attribute::Speculatable);
    }
    coverage.preparation_metric(component, "frames", count);
    coverage.preparation_metric(component, "per_invocation_bytes", total_bytes);
    coverage.preparation_metric(component, "excluded_calls", exclusions);
    return count;
}

unsigned normalize_call_frames(llvm::Function &function, const ResolvedRecipe &recipe, SiteCoverage &coverage) {
    return normalize_frame_component(function, recipe, coverage, "call-frames");
}

void hoist_call_frame_storage(llvm::Function &function) {
    std::vector<llvm::Instruction *> frames;
    for (auto &block : function) for (auto &instruction : block)
        if (instruction.getMetadata("pyobf.frame.storage") != nullptr) frames.push_back(&instruction);
    for (auto *frame : frames)
        if (frame->getParent() != &function.getEntryBlock()) frame->moveBefore(function.getEntryBlock().getFirstInsertionPt());
}

}  // namespace pyobfuscator::native::cff
