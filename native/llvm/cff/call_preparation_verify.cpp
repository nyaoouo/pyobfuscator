#include "call_preparation.hpp"
#include "ssa_origin.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
constexpr const char *tags[]{"pyobf.prep.pending", "pyobf.prep.bound", "pyobf.prep.anchor",
    "pyobf.prep.step", "pyobf.prep.step-bound", "pyobf.prep.state", "pyobf.prep.state-slot", "pyobf.prep.control"};

std::string verify_owner(const llvm::Function &function, const FrameInfo &info, const llvm::MDNode *descriptor, bool helper) {
    const llvm::Value *root = helper ? function.getArg(0) : nullptr;
    std::map<const llvm::Instruction *, std::string> events;
    std::map<unsigned, unsigned> fields;
    const auto nonempty = [&](llvm::Type *type) { return function.getParent()->getDataLayout().getTypeAllocSize(type).getFixedValue() != 0; };
    unsigned anchors = 0;
    for (const auto &block : function) for (const auto &instruction : block) {
        if (!helper && instruction.getMetadata("pyobf.frame.storage") == descriptor) {
            if (root != nullptr) return "preparation frame has multiple storage owners";
            root = &instruction;
        }
        if (const auto *anchor = instruction.getMetadata("pyobf.prep.anchor"); anchor != nullptr &&
            anchor->getNumOperands() == 2 && anchor->getOperand(0) == descriptor) {
            const auto *role = llvm::dyn_cast<llvm::MDString>(anchor->getOperand(1));
            if (role == nullptr || role->getString() != (helper ? "invoker" : "caller") ||
                instruction.getMetadata(helper ? "pyobf.frame.inner" : "pyobf.frame.invoke") != descriptor)
                return "preparation anchor lost its actual invocation";
            events.emplace(&instruction, helper ? "invoke-invoker" : "invoke-caller");
            ++anchors;
            if (helper) {
                const auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
                if (call == nullptr) return "preparation invoker is not a call";
                const auto add = [&](const llvm::Value *value, const char *label) {
                    const auto *load = llvm::dyn_cast_or_null<llvm::LoadInst>(unique_spill_origin(value));
                    if (load != nullptr && nonempty(load->getType())) events.emplace(load, label);
                };
                add(call->getCalledOperand(), "read-target");
                for (const auto &argument : call->args()) add(argument.get(), "read-argument");
            }
        }
        for (const auto name : {"pyobf.frame.target", "pyobf.frame.result", "pyobf.frame.return-store"})
            if (instruction.getMetadata(name) == descriptor && nonempty(llvm::isa<llvm::StoreInst>(instruction) ?
                instruction.getOperand(0)->getType() : instruction.getType())) events.emplace(&instruction, name);
        if (const auto *tag = instruction.getMetadata("pyobf.frame.argument"); tag != nullptr &&
            tag->getNumOperands() == 2 && tag->getOperand(0) == descriptor && nonempty(instruction.getOperand(0)->getType()))
            events.emplace(&instruction, "write-argument");
    }
    if (anchors != 1 || root == nullptr) return "preparation is missing its unique frame/invocation";
    std::set<const llvm::BasicBlock *> blocks;
    std::set<unsigned> states;
    const llvm::AllocaInst *state_slot = nullptr;
    for (const auto &block : function) for (const auto &instruction : block)
        if (instruction.getMetadata("pyobf.prep.state-slot")) {
            if (state_slot != nullptr) return "preparation has multiple state slots";
            state_slot = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
        }
    unsigned actual_events = 0;
    for (const auto &block : function) for (const auto &instruction : block) {
        if (const auto *tag = instruction.getMetadata("pyobf.prep.bound"); tag != nullptr &&
            tag->getNumOperands() == 4 && tag->getOperand(0) == descriptor) {
            const auto *address = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction);
            const auto field = address == nullptr ? std::optional<unsigned>{} : prepared_frame_field(*address, root, info.layout);
            if (!field || ++fields[*field] != 1) return "preparation address lost its exact state/field graph";
        }
        const auto expected = events.find(&instruction);
        const auto *tag = instruction.getMetadata("pyobf.prep.step-bound");
        const bool own = tag != nullptr && tag->getNumOperands() == 3 && tag->getOperand(0) == descriptor;
        if (expected == events.end() && !own) continue;
        const auto *role = own ? llvm::dyn_cast<llvm::MDString>(tag->getOperand(1)) : nullptr;
        const auto state = frame_number(tag, 2);
        if (expected == events.end() || role == nullptr || role->getString() != expected->second || !state ||
            !blocks.insert(&block).second || !states.insert(*state).second || !preparation_state_routes_to(block, state_slot, *state))
            return "preparation steps are missing, duplicated or share a state/block";
        ++actual_events;
    }
    unsigned expected_fields = 0;
    for (unsigned index = 0; index < info.layout.type->getNumElements(); ++index)
        if (index != info.layout.padding && nonempty(info.layout.type->getElementType(index))) {
            if (fields[index] != 1) return "preparation lost a nonempty field address: " + function.getName().str() + ":" + std::to_string(index);
            ++expected_fields;
        }
    if (actual_events != expected_fields + 1 || fields.size() != expected_fields)
        return "preparation field/step inventory differs from the actual typed frame";
    return {};
}

}  // namespace

std::string verify_call_preparation(const llvm::Module &module) {
    std::map<const llvm::MDNode *, std::set<const llvm::Function *>> owners;
    if (const auto *inventory = module.getNamedMetadata("pyobf.prep.inventory")) for (const auto *record : inventory->operands()) {
        const auto *descriptor = record->getNumOperands() == 3 ? llvm::dyn_cast<llvm::MDNode>(record->getOperand(0)) : nullptr;
        const auto info = read_frame_metadata(descriptor);
        const auto *owner = record->getNumOperands() == 3 ? llvm::dyn_cast<llvm::ValueAsMetadata>(record->getOperand(1)) : nullptr;
        const auto *function = owner == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(owner->getValue());
        bool frame_record = false;
        if (const auto *frames = module.getNamedMetadata("pyobf.frame.inventory"))
            for (const auto *frame : frames->operands()) if (frame == record) frame_record = true;
        if (!info || info->layout.padding == ~0u || function == nullptr || !frame_record || owners.count(descriptor))
            return "call preparation inventory lost its original frame/owner";
        owners[descriptor] = {function, info->helper};
        if (const auto reason = verify_owner(*function, *info, descriptor, false); !reason.empty()) return reason;
        if (const auto reason = verify_owner(*info->helper, *info, descriptor, true); !reason.empty()) return reason;
    }
    for (const auto &function : module) for (const auto &block : function) for (const auto &instruction : block) {
        if (instruction.getMetadata("pyobf.prep.pending") || instruction.getMetadata("pyobf.prep.step"))
            return "call preparation has an unbound address or step";
        for (const auto name : {"pyobf.prep.bound", "pyobf.prep.anchor", "pyobf.prep.step-bound"})
            if (const auto *tag = instruction.getMetadata(name)) {
                const auto arity = llvm::StringRef(name) == "pyobf.prep.bound" ? 4u : llvm::StringRef(name) == "pyobf.prep.anchor" ? 2u : 3u;
                const auto *descriptor = tag->getNumOperands() ? llvm::dyn_cast<llvm::MDNode>(tag->getOperand(0)) : nullptr;
                if (tag->getNumOperands() != arity || !owners.count(descriptor) || !owners.at(descriptor).count(&function))
                    return "call preparation artifact has no owning planned site";
            }
    }
    return {};
}

void reject_preparation_artifacts(const llvm::Module &module) {
    if (module.getNamedMetadata("pyobf.prep.inventory") != nullptr)
        llvm::report_fatal_error("native preparation: private inventory in source input");
    for (const auto &function : module) {
        for (const auto *tag : tags) if (function.getMetadata(tag)) llvm::report_fatal_error("native preparation: private source artifacts");
        for (const auto &block : function) for (const auto &instruction : block)
            for (const auto *tag : tags) if (instruction.getMetadata(tag)) llvm::report_fatal_error("native preparation: private source artifacts");
    }
}

void strip_call_preparation(llvm::Module &module) {
    for (auto &function : module) for (auto &block : function) for (auto &instruction : block)
        for (const auto *tag : tags) instruction.setMetadata(tag, nullptr);
    if (auto *inventory = module.getNamedMetadata("pyobf.prep.inventory")) module.eraseNamedMetadata(inventory);
}

}  // namespace pyobfuscator::native::cff
