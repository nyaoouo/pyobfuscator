#include "call_frames.hpp"
#include "reference_routes.hpp"
#include "ssa_origin.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
constexpr const char *tags[]{"pyobf.frame.plan", "pyobf.frame.storage", "pyobf.frame.target",
    "pyobf.frame.argument", "pyobf.frame.invoke", "pyobf.frame.result", "pyobf.frame.inner",
    "pyobf.frame.return-store", "pyobf.frame.helper", "pyobf.frame.abi"};

const llvm::Function *function_value(const llvm::Value *value) {
    value = unique_spill_origin(value);
    if (value == nullptr) return nullptr;
    if (const auto *function = llvm::dyn_cast<llvm::Function>(value)) return function;
    return resolve_reference_target(value);
}

bool helper_body(const FrameInfo &info, const llvm::MDNode *descriptor) {
    const auto *helper = info.helper;
    const auto *abi = helper->getMetadata("pyobf.frame.abi");
    if (helper->isDeclaration() || !helper->hasInternalLinkage() || helper->isVarArg() || helper->arg_size() != 1 ||
        !helper->getReturnType()->isVoidTy() || !helper->getArg(0)->getType()->isPointerTy() ||
        helper->getArg(0)->getType()->getPointerAddressSpace() != 0 || helper->getCallingConv() != llvm::CallingConv::C ||
        !helper->hasFnAttribute("pyobf.cff.transformed") || helper->getMetadata("pyobf.frame.helper") != descriptor ||
        abi == nullptr || abi->getNumOperands() != info.target->arg_size() + 3) return false;
    const llvm::CallInst *inner = nullptr;
    const llvm::StoreInst *returned = nullptr;
    for (const auto &block : *helper) for (const auto &instruction : block) {
        if (instruction.getMetadata("pyobf.frame.inner") == descriptor) {
            if (inner != nullptr) return false;
            inner = llvm::dyn_cast<llvm::CallInst>(&instruction);
        }
        if (instruction.getMetadata("pyobf.frame.return-store") == descriptor) {
            if (returned != nullptr) return false;
            returned = llvm::dyn_cast<llvm::StoreInst>(&instruction);
        }
    }
    if (inner == nullptr || inner->getFunctionType() != info.target->getFunctionType() ||
        inner->getCallingConv() != info.target->getCallingConv() || frame_number(abi, 0) != inner->getCallingConv()) return false;
    std::vector<unsigned> attribute_indices{llvm::AttributeList::FunctionIndex, llvm::AttributeList::ReturnIndex};
    for (unsigned index = 0; index < inner->arg_size(); ++index) attribute_indices.push_back(index + 1);
    for (unsigned index = 0; index < attribute_indices.size(); ++index) {
        const auto *expected = llvm::dyn_cast<llvm::MDString>(abi->getOperand(index + 1));
        if (expected == nullptr || expected->getString() != inner->getAttributes().getAsString(attribute_indices[index])) return false;
    }
    std::set<const llvm::Instruction *> allowed;
    const auto read = [&](const llvm::Value *value, unsigned index) {
        const auto *load = llvm::dyn_cast_or_null<llvm::LoadInst>(unique_spill_origin(value));
        if (load == nullptr || load->getType() != info.layout.type->getElementType(index) ||
            !is_frame_field(load->getPointerOperand(), helper->getArg(0), info.layout, index)) return false;
        allowed.insert(load);
        return true;
    };
    if (!read(inner->getCalledOperand(), info.layout.target)) return false;
    for (unsigned index = 0; index < inner->arg_size(); ++index)
        if (!read(inner->getArgOperand(index), info.layout.arguments[index])) return false;
    if (inner->getType()->isVoidTy()) { if (returned != nullptr) return false; }
    else {
        if (returned == nullptr || unique_spill_origin(returned->getValueOperand()) != inner ||
            !is_frame_field(returned->getPointerOperand(), helper->getArg(0), info.layout, info.layout.result)) return false;
        allowed.insert(returned);
    }
    return closed_frame_storage(helper->getArg(0), info.layout, allowed);
}

}  // namespace

std::string verify_call_frames(const llvm::Module &module) {
    std::map<const llvm::Function *, std::pair<const llvm::Function *, const llvm::MDNode *>> consumed;
    for (const auto &function : module) {
        std::map<const llvm::MDNode *, const llvm::AllocaInst *> frames;
        for (const auto &block : function) for (const auto &instruction : block) {
            if (instruction.getMetadata("pyobf.frame.plan") != nullptr) return "call frame plan was not consumed";
            if (const auto *descriptor = instruction.getMetadata("pyobf.frame.storage")) {
                const auto *frame = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
                const auto info = read_frame_metadata(descriptor);
                const auto *count = frame == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(frame->getArraySize());
                if (!info || frame == nullptr || frame->getAllocatedType() != info->layout.type || count == nullptr || !count->isOne() ||
                    frame->getParent() != &function.getEntryBlock() || frame->getAddressSpace() != 0 ||
                    !frames.emplace(descriptor, frame).second || !consumed.emplace(info->helper, std::make_pair(&function, descriptor)).second ||
                    !helper_body(*info, descriptor)) return "call frame storage/helper ownership or ABI is invalid";
            }
        }
        for (const auto &[descriptor, frame] : frames) {
            const auto info = *read_frame_metadata(descriptor);
            unsigned invokes = 0, targets = 0, results = 0;
            std::set<unsigned> arguments;
            std::set<const llvm::Instruction *> allowed;
            for (const auto &block : function) for (const auto &instruction : block) {
                if (instruction.getMetadata("pyobf.frame.invoke") == descriptor) {
                    const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
                    if (call == nullptr || call->arg_size() != 1 || call->getArgOperand(0) != frame ||
                        call->getFunctionType() != info.helper->getFunctionType() ||
                        call->getCallingConv() != info.helper->getCallingConv() ||
                        function_value(call->getCalledOperand()) != info.helper || !call->getType()->isVoidTy())
                        return "call frame invocation lost its owned frame or actual helper target";
                    ++invokes; allowed.insert(call);
                }
                if (instruction.getMetadata("pyobf.frame.target") == descriptor) {
                    const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
                    if (store == nullptr || !is_frame_field(store->getPointerOperand(), frame, info.layout, info.layout.target) ||
                        function_value(store->getValueOperand()) != info.target) return "call frame target storage differs";
                    ++targets; allowed.insert(store);
                }
                if (const auto *argument = instruction.getMetadata("pyobf.frame.argument");
                    argument != nullptr && argument->getNumOperands() == 2 && argument->getOperand(0) == descriptor) {
                    const auto index = frame_number(argument, 1);
                    const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
                    if (!index || *index >= info.layout.arguments.size() || !arguments.insert(*index).second || store == nullptr ||
                        store->getValueOperand()->getType() != info.target->getArg(*index)->getType() ||
                        !is_frame_field(store->getPointerOperand(), frame, info.layout, info.layout.arguments[*index]))
                        return "call frame argument storage differs";
                    allowed.insert(store);
                }
                if (instruction.getMetadata("pyobf.frame.result") == descriptor) {
                    const auto *load = llvm::dyn_cast<llvm::LoadInst>(&instruction);
                    if (load == nullptr || info.layout.result == ~0u || load->getType() != info.target->getReturnType() ||
                        !is_frame_field(load->getPointerOperand(), frame, info.layout, info.layout.result))
                        return "call frame result storage differs";
                    ++results; allowed.insert(load);
                }
            }
            if (invokes != 1 || targets != 1 || results != !info.target->getReturnType()->isVoidTy() ||
                arguments.size() != info.target->arg_size() || !closed_frame_storage(frame, info.layout, allowed))
                return "call frame accesses are missing, duplicated, shared or escaping";
        }
    }
    std::set<const llvm::Function *> inventory;
    if (const auto *records = module.getNamedMetadata("pyobf.frame.inventory")) for (const auto *record : records->operands()) {
        const auto info = record->getNumOperands() == 3 ? read_frame_metadata(llvm::dyn_cast<llvm::MDNode>(record->getOperand(0))) :
            std::optional<FrameInfo>{};
        const auto *owner = record->getNumOperands() == 3 ? llvm::dyn_cast<llvm::ValueAsMetadata>(record->getOperand(1)) : nullptr;
        const auto *site = record->getNumOperands() == 3 ? llvm::dyn_cast<llvm::MDString>(record->getOperand(2)) : nullptr;
        if (!info || owner == nullptr || site == nullptr || site->getString().empty() ||
            !inventory.insert(info->helper).second || !consumed.count(info->helper) ||
            consumed.at(info->helper).first != owner->getValue() || consumed.at(info->helper).second != record->getOperand(0))
            return "call frame inventory lost its original owner or actual invocation";
    }
    if (inventory.size() != consumed.size()) return "call frame storage is absent from the planned inventory";
    for (const auto &function : module)
        if (function.getMetadata("pyobf.frame.helper") != nullptr && !consumed.count(&function))
            return "call frame invoker has no unique owning call site";
    return {};
}

void reject_call_frame_artifacts(const llvm::Module &module) {
    if (module.getNamedMetadata("pyobf.frame.inventory") != nullptr)
        llvm::report_fatal_error("native call frames: private inventory in source input");
    for (const auto &function : module) {
        for (const auto *tag : tags) if (function.getMetadata(tag) != nullptr)
            llvm::report_fatal_error("native call frames: private helper artifacts in source input");
        for (const auto &block : function) for (const auto &instruction : block)
            for (const auto *tag : tags) if (instruction.getMetadata(tag) != nullptr)
                llvm::report_fatal_error("native call frames: private frame artifacts in source input");
    }
}

void finish_call_frames(llvm::Module &module) {
    if (const auto reason = verify_call_frames(module); !reason.empty()) llvm::report_fatal_error(llvm::StringRef(reason));
    for (auto &function : module) {
        for (const auto *tag : tags) function.setMetadata(tag, nullptr);
        for (auto &block : function) for (auto &instruction : block)
            for (const auto *tag : tags) instruction.setMetadata(tag, nullptr);
    }
    if (auto *inventory = module.getNamedMetadata("pyobf.frame.inventory")) module.eraseNamedMetadata(inventory);
}

}  // namespace pyobfuscator::native::cff
