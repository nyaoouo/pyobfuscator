#include "owner_reader_flow.hpp"

#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"

#include <map>
#include <set>
#include <vector>

namespace pyobfuscator::native::cff {
namespace {
constexpr const char *hash_name = "_ZN12pyobfuscator6native8platform11hash_sha256EPKhyPh";
constexpr const char *span_name = "_ZN12pyobfuscator6native8platform9code_spanERKNS0_11measurement10ModuleViewEjj";
constexpr const char *allocate_name = "_ZN12pyobfuscator6native8platform8allocateEy";
constexpr const char *prefix_name = "_ZN12pyobfuscator6native11measurement6detail12write_prefixERKNS1_10DescriptorEPh";
using Roots = std::set<const llvm::Value *>;
class Origins {
    std::map<const llvm::Value *, std::vector<const llvm::Value *>> slots_;
    std::map<const llvm::Value *, const llvm::Value *> copies_;
    std::set<const llvm::Value *> repeated_;
    std::set<const llvm::Value *> clobbered_;
    void collect(const llvm::Value *value, Roots &output, std::set<const llvm::Value *> &seen) const {
        if (!seen.insert(value).second) return;
        if (seen.size() > 4096) { output.insert(nullptr); return; }
        if (clobbered_.count(value) || repeated_.count(value)) { output.insert(nullptr); return; }
        if (const auto *gep = llvm::dyn_cast<llvm::GEPOperator>(value)) return collect(gep->getPointerOperand(), output, seen);
        if (const auto *cast = llvm::dyn_cast<llvm::CastInst>(value)) return collect(cast->getOperand(0), output, seen);
        if (const auto *freeze = llvm::dyn_cast<llvm::FreezeInst>(value)) return collect(freeze->getOperand(0), output, seen);
        if (const auto *phi = llvm::dyn_cast<llvm::PHINode>(value)) {
            for (const auto &operand : phi->incoming_values()) collect(operand, output, seen);
            return;
        }
        if (const auto *select = llvm::dyn_cast<llvm::SelectInst>(value)) {
            collect(select->getTrueValue(), output, seen); collect(select->getFalseValue(), output, seen); return;
        }
        if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(value); load && !load->isVolatile()) {
            const auto *slot = load->getPointerOperand()->stripPointerCasts();
            if (clobbered_.count(slot) || repeated_.count(slot)) { output.insert(nullptr); return; }
            if (const auto found = slots_.find(slot); found != slots_.end()) {
                for (const auto *stored : found->second) collect(stored, output, seen);
                return;
            }
        }
        if (const auto found = copies_.find(value); found != copies_.end()) return collect(found->second, output, seen);
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(value))
            if (const auto *target = call->getCalledFunction(); target && target->getName() == prefix_name && call->arg_size() == 2)
                return collect(call->getArgOperand(1), output, seen);
        output.insert(value);
    }
public:
    explicit Origins(const llvm::Function &function) {
        for (const auto &block : function) for (const auto &instruction : block) {
            if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
                const auto *slot = store->getPointerOperand()->stripPointerCasts();
                if (llvm::isa<llvm::AllocaInst>(slot)) slots_[slot].push_back(store->getValueOperand());
                else if (const auto *base = llvm::dyn_cast<llvm::AllocaInst>(llvm::getUnderlyingObject(slot));
                        base && (base->getAllocatedType()->isPointerTy() || base->getAllocatedType()->isIntegerTy()))
                    clobbered_.insert(base);
            }
            if (const auto *copy = llvm::dyn_cast<llvm::MemTransferInst>(&instruction)) {
                const auto *slot = llvm::dyn_cast<llvm::AllocaInst>(copy->getDest()->stripPointerCasts());
                const auto *size = llvm::dyn_cast<llvm::ConstantInt>(copy->getLength());
                if (slot && size && size->getZExtValue() == function.getParent()->getDataLayout().getTypeAllocSize(slot->getAllocatedType())) {
                    if (!copies_.emplace(slot, copy->getSource()).second) repeated_.insert(slot);
                    if (slots_.count(slot)) clobbered_.insert(slot);
                } else clobbered_.insert(llvm::getUnderlyingObject(copy->getDest()));
            } else if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
                    call && !llvm::isa<llvm::LifetimeIntrinsic>(call)) {
                for (const auto &argument : call->args()) if (argument->getType()->isPointerTy())
                    if (const auto *slot = llvm::dyn_cast<llvm::AllocaInst>(llvm::getUnderlyingObject(argument));
                            slot && (slot->getAllocatedType()->isPointerTy() || slot->getAllocatedType()->isIntegerTy()))
                        clobbered_.insert(slot);
            }
        }
        for (const auto &[slot, values] : slots_) if (copies_.count(slot)) clobbered_.insert(slot);
    }
    Roots roots(const llvm::Value *value) const { Roots output; std::set<const llvm::Value *> seen; collect(value, output, seen); return output; }
};
bool allowed(const llvm::Function &target) {
    const auto name = target.getName();
    static const std::set<std::string> names{
        hash_name, span_name, allocate_name, prefix_name,
        "_ZN12pyobfuscator6native8platform5eraseEPvy", "_ZN12pyobfuscator6native8platform7releaseEPv",
        "_ZN12pyobfuscator6native8platform17measurement_clockERNS0_11measurement11ClockSampleE",
        "_ZN12pyobfuscator6native8platform14open_code_viewEPFvvERNS0_11measurement10ModuleViewE",
        "_ZN12pyobfuscator6native11measurement6detail8validateERKNS1_10DescriptorEPKNS1_10ModuleViewERy",
        "_ZN12pyobfuscator6native11measurement7CaptureC2Ev", "_ZN12pyobfuscator6native11measurement7CaptureD1Ev",
        "_ZN12pyobfuscator6native11measurement7CaptureD2Ev",
        "_ZN12pyobfuscator6native11measurement7Capture4failENS1_6StatusE"};
    return target.isIntrinsic() || names.count(name.str());
}
}
OwnerReaderFlow check_owner_reader_flow(const llvm::Function &function, std::uint64_t key, bool capture, bool source) {
    OwnerReaderFlow result;
    const auto fail = [&](const char *reason) { result.error = reason; return result; };
    if (!function.hasFnAttribute(llvm::Attribute::NoUnwind) || function.getCallingConv() != llvm::CallingConv::C ||
        (capture && (function.arg_size() != 4 || !function.getReturnType()->isVoidTy() ||
            !function.hasParamAttribute(0, llvm::Attribute::StructRet) || !function.getArg(0)->getType()->isPointerTy() ||
            !function.getArg(1)->getType()->isPointerTy() || !function.getArg(2)->getType()->isPointerTy() ||
            !function.getArg(3)->getType()->isIntegerTy(64))) ||
        (!capture && (function.arg_size() != 2 || !function.getReturnType()->isIntegerTy(1) ||
            !function.getArg(0)->getType()->isIntegerTy(64) || !function.getArg(1)->getType()->isPointerTy())))
        return fail("owner reader has an unsupported callback ABI");
    const Origins origins(function);
    const auto *binding = function.getArg(capture ? 3 : 0);
    bool guarded = false, record_store = false;
    std::vector<const llvm::CallBase *> hashes, allocations, spans;
    std::vector<const llvm::LoadInst *> reads;
    std::vector<const llvm::StoreInst *> stores;
    for (const auto &block : function) for (const auto &instruction : block) {
        if (const auto *compare = llvm::dyn_cast<llvm::ICmpInst>(&instruction); compare && compare->isEquality())
            for (unsigned index = 0; index != 2; ++index)
                if (const auto *number = llvm::dyn_cast<llvm::ConstantInt>(compare->getOperand(index));
                        number && number->getBitWidth() == 64 && number->getZExtValue() == key &&
                        origins.roots(compare->getOperand(1 - index)) == Roots{binding}) guarded = true;
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
            const auto *target = llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCastsAndAliases());
            if (source && (!target || (!capture && !target->isIntrinsic()) || (capture && !allowed(*target)))) {
                result.error = "owner reader calls an unadmitted shared helper: " +
                    (target == nullptr ? std::string("indirect") : target->getName().str()); return result;
            }
            if (target && target->getName() == hash_name) hashes.push_back(call);
            if (target && target->getName() == allocate_name) allocations.push_back(call);
            if (target && target->getName() == span_name) spans.push_back(call);
        }
        if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
            if (load->isVolatile() && load->getType()->isIntegerTy(8)) reads.push_back(load);
            if (source) if (const auto *global = llvm::dyn_cast<llvm::GlobalVariable>(llvm::getUnderlyingObject(load->getPointerOperand()));
                    global && (capture || !global->isConstant())) return fail("owner reader loads shared result storage");
        }
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
            stores.push_back(store);
            if (!capture && origins.roots(store->getPointerOperand()) == Roots{function.getArg(1)}) record_store = true;
        }
    }
    if (source && !guarded) return fail("owner reader lost its early binding-key guard");
    if (!capture) {
        if (!record_store || !hashes.empty() || !reads.empty()) return fail("owner cache codec lacks its private record writes");
        return result;
    }
    if (hashes.size() != 1 || allocations.size() != 1 || spans.empty() || reads.empty())
        return fail("owner reader lacks an actual mapped read, private material or standard SHA");
    const auto *hash = hashes.front(), *allocation = allocations.front();
    if (hash->arg_size() != 3 || origins.roots(hash->getArgOperand(0)) != Roots{allocation} ||
            origins.roots(hash->getArgOperand(2)) != Roots{function.getArg(0)})
        return fail("owner reader SHA does not consume its own material or write its own capture");
    for (const auto *read : reads) {
        const auto roots = origins.roots(read->getPointerOperand());
        bool mapped = false, stored = false;
        for (const auto *span : spans) if (roots == Roots{span}) mapped = true;
        for (const auto *store : stores)
            if (origins.roots(store->getValueOperand()) == Roots{read} &&
                    origins.roots(store->getPointerOperand()) == Roots{allocation}) stored = true;
        if (!mapped) return fail("owner reader volatile byte address lost its exact mapped-span origin");
        if (!stored) return fail("owner reader volatile byte value does not reach its own SHA material");
    }
    result.volatile_reads = static_cast<unsigned>(reads.size());
    return result;
}
}
