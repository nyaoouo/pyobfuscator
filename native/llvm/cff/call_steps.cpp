#include "call_preparation.hpp"
#include "site_report.hpp"
#include "ssa_origin.hpp"
#include "contribution_edges.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

unsigned prepare_call_steps(llvm::Function &function, llvm::Value *, const ResolvedRecipe &, SiteCoverage &coverage) {
    std::map<llvm::Instruction *, std::pair<llvm::MDNode *, std::string>> events;
    for (auto &block : function) for (auto &instruction : block) {
        if (auto *anchor = instruction.getMetadata("pyobf.prep.anchor")) {
            auto *descriptor = llvm::dyn_cast<llvm::MDNode>(anchor->getOperand(0));
            const auto *role = llvm::dyn_cast<llvm::MDString>(anchor->getOperand(1));
            if (descriptor == nullptr || role == nullptr) llvm::report_fatal_error("invalid preparation anchor");
            events.emplace(&instruction, std::make_pair(descriptor, "invoke-" + role->getString().str()));
            if (role->getString() == "invoker") {
                auto *call = llvm::cast<llvm::CallInst>(&instruction);
                const auto add_read = [&](llvm::Value *value, const char *label) {
                    auto *source = const_cast<llvm::Value *>(unique_spill_origin(value));
                    if (auto *load = llvm::dyn_cast_or_null<llvm::LoadInst>(source))
                        if (function.getParent()->getDataLayout().getTypeAllocSize(load->getType()).getFixedValue())
                            events.emplace(load, std::make_pair(descriptor, label));
                };
                add_read(call->getCalledOperand(), "read-target");
                for (auto &argument : call->args()) add_read(argument.get(), "read-argument");
            }
        }
    }
    std::set<const llvm::MDNode *> admitted;
    for (const auto &[instruction, event] : events) admitted.insert(event.first);
    for (auto &block : function) for (auto &instruction : block) {
        for (const auto name : {"pyobf.frame.target", "pyobf.frame.result", "pyobf.frame.return-store"}) {
            auto *descriptor = instruction.getMetadata(name);
            if (descriptor == nullptr || !admitted.count(descriptor)) continue;
            auto *type = llvm::isa<llvm::StoreInst>(instruction) ? instruction.getOperand(0)->getType() : instruction.getType();
            if (function.getParent()->getDataLayout().getTypeAllocSize(type).getFixedValue())
                events.emplace(&instruction, std::make_pair(descriptor, name));
        }
        if (auto *tag = instruction.getMetadata("pyobf.frame.argument")) {
            auto *descriptor = tag->getNumOperands() == 2 ? llvm::dyn_cast<llvm::MDNode>(tag->getOperand(0)) : nullptr;
            if (descriptor != nullptr && admitted.count(descriptor) &&
                function.getParent()->getDataLayout().getTypeAllocSize(instruction.getOperand(0)->getType()).getFixedValue())
                events.emplace(&instruction, std::make_pair(descriptor, "write-argument"));
        }
    }
    std::vector<llvm::Instruction *> ordered;
    for (auto &block : function) for (auto &instruction : block) if (events.count(&instruction)) ordered.push_back(&instruction);
    unsigned created = 0;
    for (auto *event : ordered) {
        auto *body = event->getParent();
        auto *step = body->splitBasicBlock(event, "pyobf.call.prepare");
        if (coverage.contribution_edges)
            if (const auto reason = coverage.contribution_edges->completion_split(*body, *step); !reason.empty())
                llvm::report_fatal_error(llvm::StringRef(reason));
        coverage.origins().set(*step, BlockRole::routing);
        if (!event->isTerminator()) {
            auto *continuation = step->splitBasicBlock(event->getNextNode(), "pyobf.call.continue");
            if (coverage.contribution_edges)
                if (const auto reason = coverage.contribution_edges->completion_split(*step, *continuation); !reason.empty())
                    llvm::report_fatal_error(llvm::StringRef(reason));
            coverage.origins().set(*continuation, coverage.origins().get(*body));
            ++created;
        }
        event->setMetadata("pyobf.prep.step", llvm::MDNode::get(function.getContext(), {
            events.at(event).first, llvm::MDString::get(function.getContext(), events.at(event).second)}));
        ++created;
    }
    coverage.preparation_metric("call-preparation", "state_steps", ordered.size());
    coverage.preparation_metric("call-preparation", "created_blocks", created);
    return created;
}

}  // namespace pyobfuscator::native::cff
