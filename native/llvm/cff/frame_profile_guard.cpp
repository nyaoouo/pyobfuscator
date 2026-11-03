#include "frame_profile.hpp"
#include "call_frames.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

std::string FrameProfileSeal::bind(const llvm::Module &module,
    const std::map<std::string, GeneratedDefinition> &generated) {
    if (&module != module_ || bound_once_) return "frame profile plan was rebound or changed module";
    bound_once_ = true;
    std::set<const llvm::Instruction *> instructions;
    for (const auto &function : module) for (const auto &block : function) for (const auto &instruction : block)
        instructions.insert(&instruction);
    std::set<const llvm::Function *> consumed;
    for (const auto &source : sources_) {
        if (!instructions.count(source.call)) continue;
        const auto *descriptor = source.call->getMetadata("pyobf.frame.plan");
        if (descriptor == nullptr) continue;
        const auto info = read_frame_metadata(descriptor);
        if (!info || info->target != source.target || source.call->getFunction() != source.owner ||
            !consumed.insert(info->helper).second) return "frame profile source ownership changed";
        const auto found = generated.find(info->helper->getName().str());
        if (found == generated.end() || found->second.function != info->helper ||
            found->second.owner != source.owner->getName() || found->second.site.empty() ||
            found->second.component != (info->external ? "external-calls" : "call-frames"))
            return "frame profile helper has no original generation owner";
        if (profile_snapshot(source.call->getMetadata(llvm::LLVMContext::MD_prof)) != source.original)
            return "frame profile source changed during helper planning";
        const llvm::CallInst *inner = nullptr;
        for (const auto &block : *info->helper) for (const auto &instruction : block)
            if (instruction.getMetadata("pyobf.frame.inner") == descriptor) {
                if (inner != nullptr || !llvm::isa<llvm::CallInst>(instruction))
                    return "frame profile has no unique typed inner event";
                inner = llvm::cast<llvm::CallInst>(&instruction);
            }
        if (inner == nullptr || profile_snapshot(inner->getMetadata(llvm::LLVMContext::MD_prof)) != source.inner)
            return "frame profile typed inner event differs from its source";
        bound_.push_back({source.owner, info->helper, inner, descriptor, llvm::isa<llvm::InvokeInst>(source.call),
                          source.outer, source.inner});
    }
    for (const auto &[name, definition] : generated)
        if ((definition.component == "call-frames" || definition.component == "external-calls") &&
            !consumed.count(definition.function)) return "frame profile helper lost its original source";
    return {};
}

std::string FrameProfileSeal::verify(const llvm::Module &module) const {
    if (&module != module_ || !bound_once_) return "frame profile has no bound original plan";
    std::set<const llvm::Function *> functions;
    std::set<const llvm::Instruction *> instructions;
    std::map<const llvm::MDNode *, const llvm::CallBase *> outers, inners;
    for (const auto &function : module) {
        functions.insert(&function);
        for (const auto &block : function) for (const auto &instruction : block) {
            instructions.insert(&instruction);
            for (const auto &[tag, inventory] : {
                std::pair{"pyobf.frame.invoke", &outers}, std::pair{"pyobf.frame.inner", &inners}})
                if (const auto *descriptor = instruction.getMetadata(tag)) {
                    const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
                    if (call == nullptr || !inventory->emplace(descriptor, call).second)
                        return "frame profile has no unique owned call event";
                }
        }
    }
    if (outers.size() != bound_.size() || inners.size() != bound_.size()) return "frame profile event inventory changed";
    for (const auto &record : bound_) {
        if (!functions.count(record.owner) || !functions.count(record.helper) || !instructions.count(record.inner) ||
            !inners.count(record.descriptor) || inners.at(record.descriptor) != record.inner ||
            record.inner->getFunction() != record.helper || record.helper->getMetadata("pyobf.frame.helper") != record.descriptor ||
            record.inner->getMetadata("pyobf.frame.inner") != record.descriptor ||
            profile_snapshot(record.inner->getMetadata(llvm::LLVMContext::MD_prof)) != record.inner_profile)
            return "frame profile typed target event changed after binding";
        const auto found = outers.find(record.descriptor);
        const auto *outer = found == outers.end() ? nullptr : found->second;
        if (outer == nullptr || outer->getFunction() != record.owner || llvm::isa<llvm::InvokeInst>(outer) != record.invoke ||
            profile_snapshot(outer->getMetadata(llvm::LLVMContext::MD_prof)) != record.outer_profile)
            return "frame profile outer event differs from its original edge/count profile";
    }
    return {};
}

}  // namespace pyobfuscator::native::cff
