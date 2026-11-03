#include "owner_creator_flow.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

#include <map>
#include <set>

namespace pyobfuscator::native::cff {
namespace {
constexpr const char *create_name =
    "_ZN12pyobfuscator6native11measurement8observer6createEPKhyRKNS1_9reference8IdentityERA8_KjRKNS2_4SpecE";
struct TaggedCreator {
    const llvm::Function *function = nullptr;
    std::uint32_t index = 0, owner = 0;
    std::uint64_t key = 0;
    std::string plan;
};
[[noreturn]] void reject(const char *reason) { llvm::report_fatal_error(llvm::Twine("owner creator: ") + reason); }
bool hex(llvm::StringRef value, unsigned size) {
    return value.size() == size && value.find_first_not_of("0123456789abcdef") == llvm::StringRef::npos;
}
const llvm::Value *base(const llvm::Value *pointer, int64_t &offset, const llvm::DataLayout &layout) {
    offset = 0;
    return llvm::GetPointerBaseWithConstantOffset(pointer, offset, layout);
}
std::vector<TaggedCreator> collect(const llvm::Module &module) {
    std::vector<TaggedCreator> result;
    const auto *annotations = module.getNamedGlobal("llvm.global.annotations");
    if (annotations == nullptr || !annotations->hasInitializer()) return result;
    const auto *rows = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
    if (rows == nullptr) reject("typed source annotations are missing");
    std::set<const llvm::Function *> claimed;
    for (const auto &operand : rows->operands()) {
        const auto *row = llvm::dyn_cast<llvm::Constant>(operand);
        const auto *label = row == nullptr ? nullptr : row->getAggregateElement(1u);
        const auto *global = label == nullptr ? nullptr : llvm::dyn_cast<llvm::GlobalVariable>(label->stripPointerCasts());
        const auto *data = global == nullptr || !global->hasInitializer() ? nullptr :
            llvm::dyn_cast<llvm::ConstantDataSequential>(global->getInitializer());
        if (data == nullptr || !data->isCString()) continue;
        auto text = data->getAsCString();
        if (!text.consume_front("pyobf.native.owner.creator.v1:")) continue;
        llvm::SmallVector<llvm::StringRef, 4> fields; text.split(fields, ':');
        TaggedCreator creator;
        if (fields.size() != 4 || fields[0].getAsInteger(10, creator.index) || creator.index >= 64 ||
                fields[1].getAsInteger(10, creator.owner) || creator.owner == 0 ||
                !hex(fields[2], 16) || fields[2].getAsInteger(16, creator.key) || creator.key == 0 ||
                !hex(fields[3], 64) || fields[0] != std::to_string(creator.index) ||
                fields[1] != std::to_string(creator.owner)) reject("typed role annotation is malformed");
        creator.plan = fields[3].str();
        const auto *target = row->getAggregateElement(0u);
        creator.function = target == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(target->stripPointerCastsAndAliases());
        if (creator.function == nullptr || creator.function->isDeclaration() || !claimed.insert(creator.function).second)
            reject("roles need distinct actual creator definitions");
        result.push_back(std::move(creator));
    }
    return result;
}
void check(const llvm::Function &function, const OwnerReaderBinding &binding) {
    const auto &layout = function.getParent()->getDataLayout();
    if (!function.hasFnAttribute(llvm::Attribute::NoUnwind) || function.getCallingConv() != llvm::CallingConv::C ||
            function.arg_size() != 8 || !function.hasParamAttribute(0, llvm::Attribute::StructRet))
        reject("unsupported creation ABI");
    const llvm::CallBase *creation = nullptr;
    for (const auto &block : function) for (const auto &instruction : block)
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
                call && llvm::isa<llvm::Function>(call->getCalledOperand()->stripPointerCastsAndAliases()) &&
                llvm::cast<llvm::Function>(call->getCalledOperand()->stripPointerCastsAndAliases())->getName() == create_name) {
            if (creation != nullptr || call->arg_size() != 6) reject("creator must call observer::create exactly once");
            creation = call;
        }
    if (creation == nullptr) reject("creator does not call observer::create");
    int64_t spec_offset = 0;
    const auto *spec = llvm::dyn_cast<llvm::AllocaInst>(base(creation->getArgOperand(5), spec_offset, layout));
    auto *type = spec == nullptr ? nullptr : llvm::dyn_cast<llvm::StructType>(spec->getAllocatedType());
    if (spec_offset != 0 || type == nullptr || !type->hasName() ||
            !type->getName().contains("measurement::observer::Spec") || type->getNumElements() != 4 ||
            layout.getTypeAllocSize(type) != 48 || layout.getStructLayout(type)->getElementOffset(3) != 40)
        reject("observer::create did not receive an exact local Spec");
    const llvm::StoreInst *reader = nullptr;
    const llvm::DominatorTree dominators(const_cast<llvm::Function &>(function));
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
        if (store == nullptr) continue;
        int64_t offset = 0;
        if (base(store->getPointerOperand(), offset, layout) != spec) {
            if (llvm::getUnderlyingObject(store->getPointerOperand()) == spec)
                reject("creator Spec has a variable-offset store");
            continue;
        }
        const auto width = layout.getTypeStoreSize(store->getValueOperand()->getType());
        if (width.isScalable() || offset < 0) reject("creator Spec has an ambiguous store");
        if (offset + static_cast<int64_t>(width.getFixedValue()) <= 40 || offset >= 48) continue;
        if (reader != nullptr || offset != 40 || width.getFixedValue() != 8 || !store->isSimple())
            reject("creator Spec reader has multiple or partial writes");
        int64_t binding_offset = 0;
        if (base(store->getValueOperand(), binding_offset, layout) != binding.table ||
                binding_offset != 32 * binding.index) reject("creator selected the wrong binding row");
        reader = store;
    }
    if (reader == nullptr || !dominators.dominates(reader, creation))
        reject("fixed binding row does not dominate observer::create");
    for (const auto &block : function) for (const auto &instruction : block) {
        if (const auto *transfer = llvm::dyn_cast<llvm::MemIntrinsic>(&instruction)) {
            int64_t offset = 0;
            if (base(transfer->getDest(), offset, layout) == spec) {
                const auto *size = llvm::dyn_cast<llvm::ConstantInt>(transfer->getLength());
                if (size == nullptr || offset < 0 || (offset < 48 && offset + static_cast<int64_t>(size->getZExtValue()) > 40))
                    reject("creator Spec reader is clobbered by a memory intrinsic");
            } else if (llvm::getUnderlyingObject(transfer->getDest()) == spec)
                reject("creator Spec has a variable-offset memory intrinsic");
            if (const auto *copy = llvm::dyn_cast<llvm::MemTransferInst>(transfer);
                    copy && llvm::getUnderlyingObject(copy->getSource()) == spec)
                reject("creator Spec escapes through a memory intrinsic");
        } else if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
            if (call == creation || llvm::isa<llvm::LifetimeIntrinsic>(call)) continue;
            for (const auto &argument : call->args())
                if (argument->getType()->isPointerTy() && llvm::getUnderlyingObject(argument) == spec)
                    reject("creator Spec escapes to an unadmitted call");
        } else if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
            if (store->getValueOperand()->getType()->isPointerTy() &&
                    llvm::getUnderlyingObject(store->getValueOperand()) == spec)
                reject("creator Spec pointer escapes to storage");
        }
    }
}
std::set<const llvm::Function *> used_by_producers(const llvm::Module &module,
        const std::set<const llvm::Function *> &admitted, const std::set<std::string> *selected) {
    std::set<const llvm::Function *> used;
    for (const auto &function : module) for (const auto &block : function) for (const auto &instruction : block)
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
            const auto *target = llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCastsAndAliases());
            if (target == nullptr) continue;
            if (target->getName() == create_name && !admitted.count(&function))
                reject("raw observer::create bypasses the generated creator family");
            const bool producer = !admitted.count(&function) && (selected == nullptr ?
                function.hasFnAttribute("pyobf.cff.transformed") : selected->count(function.getName().str()) != 0);
            if (admitted.count(target) && producer) used.insert(target);
        }
    return used;
}
}
OwnerCreatorSeal::OwnerCreatorSeal(const llvm::Module &module, const std::set<std::string> &selected) {
    const auto bindings = collect_owner_readers(module);
    const auto tagged = collect(module);
    if (bindings.empty() && tagged.empty()) return;
    if (bindings.size() != tagged.size()) reject("each reader owner needs one typed creator");
    std::map<std::pair<std::string, unsigned>, TaggedCreator> keyed;
    for (const auto &creator : tagged)
        if (!keyed.emplace(std::make_pair(creator.plan, creator.index), creator).second)
            reject("duplicate creator role");
    std::set<const llvm::Function *> admitted;
    for (const auto &binding : bindings) {
        const auto found = keyed.find({binding.plan, binding.index});
        if (found == keyed.end() || found->second.owner != binding.owner || found->second.key != binding.key)
            reject("creator domain differs from its reader binding");
        const auto *function = found->second.function;
        if (!selected.count(function->getName().str())) reject("creator is not selected for CFF");
        check(*function, binding);
        admitted.insert(function);
        creators_.push_back({function, binding});
    }
    if (used_by_producers(module, admitted, &selected) != admitted)
        reject("a tagged creator is unused by selected producer code");
}
llvm::json::Object OwnerCreatorSeal::verify(const llvm::Module &module) const {
    const auto tagged = collect(module);
    if (tagged.size() != creators_.size()) reject("creator roles changed during transformation");
    llvm::json::Array entries;
    std::set<const llvm::Function *> admitted;
    for (const auto &creator : creators_) {
        const auto *function = creator.function;
        bool same = false;
        for (const auto &item : tagged)
            if (item.function == function && item.index == creator.binding.index && item.owner == creator.binding.owner &&
                    item.key == creator.binding.key && item.plan == creator.binding.plan) same = true;
        if (!same) reject("creator annotation changed during transformation");
        if (!function->hasFnAttribute("pyobf.cff.transformed")) reject("creator lost selected CFF code");
        check(*function, creator.binding);
        admitted.insert(function);
        entries.push_back(llvm::json::Object{{"index", creator.binding.index}, {"owner", creator.binding.owner},
            {"plan_sha256", creator.binding.plan}, {"function", function->getName()},
            {"fixed_binding_row_verified", true}, {"direct_create_verified", true}});
    }
    if (used_by_producers(module, admitted, nullptr) != admitted)
        reject("a tagged creator lost its transformed producer call");
    return llvm::json::Object{{"schema_version", 1}, {"scheme", "source-owned-creator-v1"},
        {"entries", std::move(entries)}};
}
}
