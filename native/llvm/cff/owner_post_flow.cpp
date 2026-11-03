#include "owner_post_flow.hpp"

#include "owner_reader_bindings.hpp"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"

#include <array>
#include <optional>

namespace pyobfuscator::native::cff {
namespace {
constexpr const char *identities_name = "_ZN12pyobfuscator6native11measurement8reserved10identitiesE";
constexpr const char *data_name = "_ZN12pyobfuscator6native11measurement8reserved4dataE";
constexpr const char *offsets_name = "_ZN12pyobfuscator6native11measurement8reserved7offsetsE";
constexpr const char *material_offsets_name = "_ZN12pyobfuscator6native11measurement8reserved16material_offsetsE";
constexpr const char *producer_fragment = "prepare_post_roleILj";
constexpr const char *prepare_name = "_ZN12pyobfuscator6native4demo12prepare_postERNS1_14RuntimeSessionEPFvvE";
[[noreturn]] void reject(const char *reason) { llvm::report_fatal_error(llvm::Twine("post role flow: ") + reason); }
void require(bool condition, const char *reason) { if (!condition) reject(reason); }

const llvm::Function *callee(const llvm::CallBase &call) {
    return llvm::dyn_cast<llvm::Function>(call.getCalledOperand()->stripPointerCastsAndAliases());
}
const llvm::CallBase *one_call(const llvm::Function &function, llvm::StringRef fragment) {
    const llvm::CallBase *found = nullptr;
    for (const auto &block : function) for (const auto &instruction : block)
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
            const auto *target = callee(*call);
            if (target == nullptr || !target->getName().contains(fragment)) continue;
            require(found == nullptr, "duplicate required call");
            found = call;
        }
    require(found != nullptr, "required call is missing");
    return found;
}
llvm::StructType *named(const llvm::Module &module, llvm::StringRef suffix) {
    for (auto *type : module.getIdentifiedStructTypes())
        if (type->hasName() && type->getName().ends_with(suffix)) return type;
    reject("required ABI structure is absent");
}
std::uint64_t size_of(const llvm::DataLayout &layout, llvm::Type *type) {
    const auto size = layout.getTypeAllocSize(type);
    require(!size.isScalable(), "scalable ABI structure is unsupported");
    return size.getFixedValue();
}
struct Offsets {
    std::int64_t owners, leases, roles, preparation;
    std::uint64_t owner_size, lease_size, role_size, identity_size;
};
Offsets offsets(const llvm::Module &module) {
    const auto &layout = module.getDataLayout();
    require(layout.isLittleEndian() && layout.getPointerSize() == 8, "Windows x64 pointer layout is required");
    auto *session = named(module, "demo::RuntimeSession");
    auto *post = named(module, "demo::PostSession");
    auto *handoff = named(module, "demo::PostHandoff");
    auto *role = named(module, "demo::PostRole");
    auto *owner = named(module, "native::BootstrapContextOwner");
    auto *lease = named(module, "native::BootstrapContextLease");
    auto *identity = named(module, "reference::Identity");
    require(session->getNumElements() >= 6 && post->getNumElements() >= 5 &&
        handoff->getNumElements() == 4 && role->getNumElements() == 4,
        "post ABI structure changed");
    const auto post_offset = layout.getStructLayout(session)->getElementOffset(5);
    const auto handoff_offset = layout.getStructLayout(post)->getElementOffset(2);
    Offsets result{static_cast<std::int64_t>(post_offset + layout.getStructLayout(post)->getElementOffset(0)),
        static_cast<std::int64_t>(post_offset + layout.getStructLayout(post)->getElementOffset(1)),
        static_cast<std::int64_t>(post_offset + handoff_offset + layout.getStructLayout(handoff)->getElementOffset(3)),
        static_cast<std::int64_t>(post_offset + layout.getStructLayout(post)->getElementOffset(4)),
        size_of(layout, owner), size_of(layout, lease), size_of(layout, role), size_of(layout, identity)};
    require(result.owner_size == 8 && result.lease_size == 16 && result.role_size == 96 &&
        result.identity_size == 52, "post role or observer identity ABI changed");
    return result;
}
struct Address { const llvm::Value *root = nullptr; std::int64_t offset = 0; };
Address address_impl(const llvm::Value *value, const llvm::Function &function, unsigned depth) {
    require(depth < 6, "local pointer origin chain is too deep");
    std::int64_t offset = 0;
    const auto *root = llvm::GetPointerBaseWithConstantOffset(value, offset, function.getParent()->getDataLayout());
    if (root == function.getArg(0) || root == function.getArg(1)) return {root, offset};
    if (const auto *load = llvm::dyn_cast_or_null<llvm::LoadInst>(root)) {
        const auto *slot = llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand()->stripPointerCasts());
        if (slot != nullptr) {
            const llvm::StoreInst *store = nullptr;
            for (const auto *use : slot->users())
                if (const auto *candidate = llvm::dyn_cast<llvm::StoreInst>(use)) {
                    require(candidate->getPointerOperand() == slot, "local pointer origin escapes through a store");
                    require(store == nullptr, "session pointer local has multiple stores");
                    store = candidate;
                } else if (const auto *reader = llvm::dyn_cast<llvm::LoadInst>(use)) {
                    require(reader->getPointerOperand() == slot, "local pointer origin has an indirect read");
                } else if (!llvm::isa<llvm::LifetimeIntrinsic>(use))
                    reject("local pointer origin escapes its stack slot");
            if (store != nullptr && store->getValueOperand()->getType()->isPointerTy()) {
                const auto source = address_impl(store->getValueOperand(), function, depth + 1);
                return {source.root, source.offset + offset};
            }
        }
    }
    return {root, offset};
}
Address address(const llvm::Value *value, const llvm::Function &function) {
    return address_impl(value, function, 0);
}
bool at(const llvm::Value *value, const llvm::Function &function, const llvm::Value *root, std::int64_t offset) {
    const auto actual = address(value, function);
    return actual.root == root && actual.offset == offset;
}
std::uint64_t constant(const llvm::Value *value) {
    const auto *number = llvm::dyn_cast<llvm::ConstantInt>(value);
    require(number != nullptr, "a fixed post role field became dynamic");
    return number->getZExtValue();
}
std::uint64_t array_word(const llvm::GlobalVariable *array, unsigned index) {
    require(array && array->isConstant() && array->hasInitializer(), "reserved offset array is missing");
    const auto *entry = array->getInitializer()->getAggregateElement(index);
    require(entry != nullptr, "reserved offset index is absent");
    return constant(entry);
}
std::optional<std::uint64_t> reserved_pointer(const llvm::Value *value, const llvm::Function &function,
        const llvm::GlobalVariable *data, const llvm::GlobalVariable *offsets,
        unsigned slot) {
    const auto direct = address(value, function);
    if (direct.root == data && direct.offset >= 0) {
        if (offsets && static_cast<std::uint64_t>(direct.offset) != array_word(offsets, slot)) return std::nullopt;
        return direct.offset;
    }
    const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(value);
    if (gep == nullptr || !offsets || gep->getNumIndices() != 1 || gep->getPointerOperand() != data)
        return std::nullopt;
    const auto *load = llvm::dyn_cast<llvm::LoadInst>(gep->idx_begin()->get());
    if (!load || !at(load->getPointerOperand(), function, offsets, slot * 8)) return std::nullopt;
    return array_word(offsets, slot);
}
bool identity_pointer(const llvm::Value *value, const llvm::Function &function,
        const llvm::GlobalVariable *identities, unsigned slot, const Offsets &layout) {
    return at(value, function, identities, slot * layout.identity_size);
}
bool identity_owner(const llvm::GlobalVariable *identities, unsigned slot, std::uint32_t owner) {
    if (identities == nullptr || !identities->isConstant() || !identities->hasInitializer()) return false;
    const auto *entry = llvm::dyn_cast_or_null<llvm::ConstantStruct>(identities->getInitializer()->getAggregateElement(slot));
    const auto *field = entry == nullptr ? nullptr : llvm::dyn_cast_or_null<llvm::ConstantInt>(entry->getAggregateElement(2u));
    return field && field->getZExtValue() == owner;
}
void before(const llvm::Instruction *first, const llvm::Instruction *second, const llvm::DominatorTree &tree) {
    require(first && second && tree.dominates(first, second), "role dataflow does not dominate handoff publication");
}
bool reaches(const llvm::BasicBlock *start, const llvm::BasicBlock *destination) {
    llvm::SmallPtrSet<const llvm::BasicBlock *, 16> visited;
    llvm::SmallVector<const llvm::BasicBlock *, 16> pending{start};
    while (!pending.empty()) {
        const auto *block = pending.pop_back_val();
        if (block == destination) return true;
        if (!visited.insert(block).second) continue;
        for (const auto *successor : llvm::successors(block)) pending.push_back(successor);
    }
    return false;
}
const llvm::CallBase *call_with_target(const llvm::Function &function, llvm::StringRef fragment,
        const llvm::Value *arg, unsigned operand, std::int64_t offset) {
    const llvm::CallBase *found = nullptr;
    for (const auto &block : function) for (const auto &instruction : block)
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
            const auto *target = callee(*call);
            if (!target || !target->getName().contains(fragment) || call->arg_size() <= operand ||
                !at(call->getArgOperand(operand), function, arg, offset)) continue;
            require(found == nullptr, "role has duplicate target calls");
            found = call;
        }
    require(found != nullptr, "role target call is missing");
    return found;
}
struct CheckedRole {
    unsigned role = 0, creator_index = 0;
    std::uint32_t owner = 0, routing_tag = 0, domain = 0, source = 0;
    std::uint64_t code_offset = 0, material_offset = 0;
    std::string producer, creator, plan;
};
CheckedRole check_role(const llvm::Function &function, unsigned role, const OwnerReaderBinding &binding,
        const Offsets &layout, bool source_order) {
    require(function.arg_size() == 2 && function.getCallingConv() == llvm::CallingConv::C &&
        function.hasFnAttribute(llvm::Attribute::NoUnwind), "POST producer ABI changed");
    const auto &module = *function.getParent();
    const auto *identities = module.getNamedGlobal(identities_name);
    const auto *data = module.getNamedGlobal(data_name);
    const auto *code_offsets = module.getNamedGlobal(offsets_name);
    const auto *material_offsets = module.getNamedGlobal(material_offsets_name);
    require(identities && data && identity_owner(identities, binding.index, binding.owner),
        "role identity or reserved data disagrees with its early owner");
    const auto *create = one_call(function, "8create_");
    const auto *creator = callee(*create);
    const auto generated = "generated_" + binding.plan.substr(0, 24) + "8create_" + std::to_string(binding.index) + "E";
    require(creator && creator->getName().contains(generated) && create->arg_size() == 8,
        "role called the wrong generated creator");
    const auto *created = llvm::dyn_cast<llvm::AllocaInst>(create->getArgOperand(0)->stripPointerCasts());
    const auto code_offset = reserved_pointer(create->getArgOperand(1), function, data, code_offsets, binding.index);
    require(created && identity_pointer(create->getArgOperand(3), function, identities, binding.index, layout) &&
        code_offset && constant(create->getArgOperand(2)) == 4096,
        "creator image or identity input belongs to another role");
    if (role == 0) require(create->getArgOperand(6)->stripPointerCastsAndAliases() == module.getFunction(prepare_name),
        "wrapper creator observes another parent member");
    else require(at(create->getArgOperand(6), function, function.getArg(1), 0),
        "compute creator observes another child member");
    const auto *move = call_with_target(function, "observer8CreationaSEOS3_", created, 1, 0);
    const auto *made = llvm::dyn_cast<llvm::AllocaInst>(move->getArgOperand(0)->stripPointerCasts());
    require(made && move->arg_size() == 2, "created owner has no unique local move");
    const auto *session = function.getArg(0);
    const auto owner_at = layout.owners + role * layout.owner_size;
    const auto lease_at = layout.leases + role * layout.lease_size;
    const auto role_at = layout.roles + role * layout.role_size;
    const auto *owner_move = call_with_target(function, "BootstrapContextOwneraSEOS1_", session, 0, owner_at);
    require(owner_move->arg_size() == 2 && at(owner_move->getArgOperand(1), function, made, 16),
        "creator owner did not enter its fixed owner slot");
    const auto *lease = call_with_target(function, "BootstrapContextOwner5leaseEv", session, 1, owner_at);
    require(lease->arg_size() == 2, "owner lease ABI changed");
    const auto *temporary_lease = llvm::dyn_cast<llvm::AllocaInst>(lease->getArgOperand(0)->stripPointerCasts());
    require(temporary_lease != nullptr, "owner lease has no local result");
    const auto *lease_move = call_with_target(function, "BootstrapContextLeaseaSEOS1_", session, 0, lease_at);
    require(lease_move->arg_size() == 2 && at(lease_move->getArgOperand(1), function, temporary_lease, 0),
        "owner lease did not enter its fixed lease slot");
    const llvm::Value *stage = session;
    std::int64_t stage_offset = role_at;
    const llvm::Instruction *publication = nullptr;
    for (const auto &block : function) for (const auto &instruction : block)
        if (const auto *copy = llvm::dyn_cast<llvm::MemTransferInst>(&instruction);
                copy && at(copy->getDest(), function, session, role_at)) {
            require(publication == nullptr && constant(copy->getLength()) == layout.role_size,
                "role handoff has duplicate or partial copies");
            const auto source = address(copy->getSource(), function);
            require(llvm::isa<llvm::AllocaInst>(source.root) && source.offset == 0,
                "role handoff copy has an untracked source");
            stage = source.root; stage_offset = 0; publication = copy;
        }
    const llvm::Instruction *field[7]{};
    std::array<std::uint32_t, 4> spec{};
    std::optional<std::uint64_t> material_offset;
    const llvm::Instruction *identity_copy = nullptr;
    for (const auto &block : function) for (const auto &instruction : block) {
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
            const auto position = address(store->getPointerOperand(), function);
            if (position.root != stage || position.offset < stage_offset || position.offset >= stage_offset + 96) continue;
            const auto relative = position.offset - stage_offset;
            if (relative == 0 && store->getValueOperand()->getType()->isVectorTy()) {
                const auto *vector = llvm::dyn_cast<llvm::Constant>(store->getValueOperand());
                require(vector && field[0] == nullptr, "role spec has duplicate vector writes");
                for (unsigned index = 0; index != 4; ++index) {
                    const auto *part = llvm::dyn_cast_or_null<llvm::ConstantInt>(vector->getAggregateElement(index));
                    require(part && part->getBitWidth() == 32, "role spec vector is not four fixed words");
                    spec[index] = part->getZExtValue();
                    field[index] = store;
                }
            } else if (relative < 16 && relative % 4 == 0) {
                const auto index = relative / 4;
                require(field[index] == nullptr && store->getValueOperand()->getType()->isIntegerTy(32),
                    "role spec word has duplicate or wrong-width writes");
                spec[index] = constant(store->getValueOperand()); field[index] = store;
            } else if (relative == 72 || relative == 80 || relative == 88) {
                const unsigned index = relative == 72 ? 4 : relative == 80 ? 5 : 6;
                require(field[index] == nullptr, "role handoff field has duplicate writes");
                if (index == 4) require(at(store->getValueOperand(), function, session, lease_at),
                    "handoff observation points to another lease");
                if (index == 5) {
                    material_offset = reserved_pointer(store->getValueOperand(), function, data,
                        material_offsets, binding.index);
                    require(material_offset.has_value(), "handoff material points to another role");
                }
                if (index == 6) require(store->getValueOperand()->getType()->isIntegerTy(64) &&
                    constant(store->getValueOperand()) == 168, "handoff material length changed");
                field[index] = store;
            } else reject("role staging has an unrecognized write");
        } else if (const auto *copy = llvm::dyn_cast<llvm::MemTransferInst>(&instruction);
                copy && at(copy->getDest(), function, stage, stage_offset + 16)) {
            require(identity_copy == nullptr && constant(copy->getLength()) == layout.identity_size &&
                identity_pointer(copy->getSource(), function, identities, binding.index, layout),
                "role spec reference differs from creator identity");
            identity_copy = copy;
        }
    }
    require(identity_copy && material_offset && *material_offset == *code_offset + 4096 &&
        spec[0] && spec[1] && spec[2] == binding.owner && spec[3],
        "role spec route/source/owner is absent or malformed");
    for (const auto &block : function) for (const auto &instruction : block) {
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
            if (stage != session) {
                const auto target = address(store->getPointerOperand(), function);
                require(target.root != session || target.offset < role_at || target.offset >= role_at + 96,
                    "handoff role is overwritten outside its complete copy");
            }
        } else if (const auto *memory = llvm::dyn_cast<llvm::MemIntrinsic>(&instruction)) {
            const auto target = address(memory->getDest(), function);
            if (target.root == stage && target.offset >= stage_offset && target.offset < stage_offset + 96)
                require(memory == identity_copy, "role staging has an unrecognized memory write");
            if (target.root == session && target.offset >= role_at && target.offset < role_at + 96 &&
                    (stage != session || memory != identity_copy))
                require(memory == publication, "handoff role is overwritten outside its complete copy");
        } else if (const auto *atomic = llvm::dyn_cast<llvm::AtomicRMWInst>(&instruction)) {
            const auto target = address(atomic->getPointerOperand(), function);
            require((target.root != stage || target.offset < stage_offset || target.offset >= stage_offset + 96) &&
                (target.root != session || target.offset < role_at || target.offset >= role_at + 96),
                "role has an untracked atomic write");
        } else if (const auto *atomic = llvm::dyn_cast<llvm::AtomicCmpXchgInst>(&instruction)) {
            const auto target = address(atomic->getPointerOperand(), function);
            require((target.root != stage || target.offset < stage_offset || target.offset >= stage_offset + 96) &&
                (target.root != session || target.offset < role_at || target.offset >= role_at + 96),
                "role has an untracked compare-exchange");
        }
    }
    for (const auto *item : field) require(item != nullptr, "role field is missing");
    // CFF replaces ordinary dominators with a state dispatcher. Check source ordering before
    // transformation, then recheck every exact call, slot and field after transformation.
    if (source_order) {
        const llvm::DominatorTree tree(const_cast<llvm::Function &>(function));
        before(create, move, tree); before(move, owner_move, tree); before(owner_move, lease, tree);
        before(lease, lease_move, tree);
        const auto *previous = owner_move->getParent()->getSinglePredecessor();
        const auto *gate = previous == nullptr ? nullptr : llvm::dyn_cast<llvm::BranchInst>(previous->getTerminator());
        require(gate && gate->isConditional() && (gate->getSuccessor(0) == owner_move->getParent() ||
            gate->getSuccessor(1) == owner_move->getParent()), "created status did not gate role storage");
        const auto *comparison = llvm::dyn_cast<llvm::ICmpInst>(gate->getCondition());
        require(comparison && comparison->isEquality() &&
            (llvm::isa<llvm::ConstantInt>(comparison->getOperand(0)) ||
            llvm::isa<llvm::ConstantInt>(comparison->getOperand(1))), "creator status gate is not an equality check");
        const auto *tested = llvm::dyn_cast<llvm::LoadInst>(llvm::isa<llvm::ConstantInt>(comparison->getOperand(0)) ?
            comparison->getOperand(1) : comparison->getOperand(0));
        require(tested && at(tested->getPointerOperand(), function, made, 0) &&
            constant(llvm::isa<llvm::ConstantInt>(comparison->getOperand(0)) ? comparison->getOperand(0) :
                comparison->getOperand(1)) == 0, "creator status gate is disconnected from its result");
        const bool success_first = gate->getSuccessor(0) == owner_move->getParent();
        require((comparison->getPredicate() == llvm::CmpInst::ICMP_EQ) == success_first,
            "nonzero creator status reaches role storage");
        for (const auto *item : field) {
            require(item->getParent() == owner_move->getParent(), "role field escapes the guarded success block");
            before(lease_move, item, tree);
            if (publication) before(item, publication, tree);
        }
        require(identity_copy->getParent() == owner_move->getParent(), "identity copy escapes guarded success block");
        before(lease_move, identity_copy, tree);
        if (publication) before(identity_copy, publication, tree);
    }
    return {role, binding.index, binding.owner, spec[0], spec[1], spec[3], *code_offset, *material_offset,
        function.getName().str(), creator->getName().str(), binding.plan};
}
std::vector<CheckedRole> check(const llvm::Module &module, const std::set<std::string> *selected) {
    std::array<const llvm::Function *, 2> producers{};
    for (const auto &function : module) for (unsigned role = 0; role != 2; ++role)
        if (function.getName().contains(std::string(producer_fragment) + std::to_string(role) + "EEE")) {
            require(producers[role] == nullptr && !function.isDeclaration(), "duplicate or declaration-only role producer");
            producers[role] = &function;
        }
    if (!producers[0] && !producers[1]) return {};
    require(producers[0] && producers[1], "POST needs both fixed role producers");
    const auto bindings = collect_owner_readers(module);
    require((bindings.size() == 2 || bindings.size() == 3) &&
        bindings[0].plan == bindings.back().plan, "POST needs its exact early owner plan");
    const auto *entry = module.getFunction(prepare_name);
    require(entry && !entry->isDeclaration() && entry->arg_size() == 2,
        "POST preparation entry is missing or changed its ABI");
    std::array<const llvm::CallBase *, 2> calls{};
    for (const auto &block : *entry) for (const auto &instruction : block)
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
            for (unsigned role = 0; role != 2; ++role)
                if (callee(*call) == producers[role]) {
                    require(calls[role] == nullptr && call->arg_size() == 2,
                        "POST role producer has duplicate or malformed entry call");
                    calls[role] = call;
                }
    require(calls[0] && calls[1], "POST role producers are unused");
    if (selected) {
        const llvm::DominatorTree tree(const_cast<llvm::Function &>(*entry));
        require(tree.dominates(calls[0], calls[1]), "POST role producers are out of order");
        const llvm::CallBase *publication = nullptr;
        for (const auto &block : *entry) for (const auto &instruction : block)
            if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
                const auto *target = callee(*call);
                if (target && target->getName().contains("8platform14atomic_store32E") &&
                        call->arg_size() == 2 && llvm::isa<llvm::ConstantInt>(call->getArgOperand(1)) &&
                        constant(call->getArgOperand(1)) == 2) {
                    require(publication == nullptr, "POST has duplicate ready publications");
                    publication = call;
                }
            }
        require(publication != nullptr, "POST ready publication is missing");
        for (unsigned role = 0; role != 2; ++role) {
            const auto *call = calls[role];
            const auto *branch = llvm::dyn_cast<llvm::BranchInst>(call->getParent()->getTerminator());
            require(at(call->getArgOperand(0), *entry, entry->getArg(0), 0) &&
                (role == 0 || at(call->getArgOperand(1), *entry, entry->getArg(1), 0)) &&
                branch && branch->isConditional() && branch->getCondition() == call &&
                tree.dominates(call, publication) &&
                reaches(branch->getSuccessor(0), publication->getParent()) &&
                !reaches(branch->getSuccessor(1), publication->getParent()),
                "POST ready publication is not gated by its role result");
        }
    }
    std::vector<CheckedRole> result;
    const auto layout = offsets(module);
    for (unsigned role = 0; role != 2; ++role) {
        const auto *producer = producers[role];
        require((selected ? selected->count(producer->getName().str()) != 0 :
            producer->hasFnAttribute("pyobf.cff.transformed")), "POST producer has no selected CFF code");
        result.push_back(check_role(*producer, role, bindings[bindings.size() - 2 + role], layout,
            selected != nullptr));
    }
    require(result[0].code_offset < result[1].code_offset &&
        result[0].material_offset < result[1].material_offset,
        "POST roles reuse or reorder reserved code/material slots");
    return result;
}
}
PostRoleFlowSeal::PostRoleFlowSeal(const llvm::Module &module, const std::set<std::string> &selected) {
    for (const auto &row : check(module, &selected)) roles_.push_back({row.role, row.creator_index, row.owner,
        row.routing_tag, row.domain, row.source, row.code_offset, row.material_offset,
        row.producer, row.creator, row.plan});
}
llvm::json::Object PostRoleFlowSeal::verify(const llvm::Module &module) const {
    const auto current = check(module, nullptr);
    require(current.size() == roles_.size(), "POST role inventory changed during CFF");
    llvm::json::Array rows;
    for (unsigned index = 0; index != current.size(); ++index) {
        const auto &row = current[index];
        const auto &saved = roles_[index];
        require(row.role == saved.role && row.creator_index == saved.creator_index && row.owner == saved.owner &&
            row.routing_tag == saved.routing_tag && row.domain == saved.domain && row.source == saved.source &&
            row.code_offset == saved.code_offset && row.material_offset == saved.material_offset &&
            row.producer == saved.producer && row.creator == saved.creator && row.plan == saved.plan,
            "POST role flow changed during CFF");
        rows.push_back(llvm::json::Object{{"role", row.role}, {"creator_index", row.creator_index},
            {"owner", row.owner}, {"producer", row.producer}, {"creator", row.creator},
            {"routing_tag", row.routing_tag}, {"domain", row.domain}, {"source", row.source},
            {"code_offset", row.code_offset}, {"material_offset", row.material_offset},
            {"creator_result_to_owner_verified", true}, {"owner_to_lease_verified", true},
            {"lease_to_handoff_verified", true}, {"spec_identity_material_verified", true}});
    }
    return llvm::json::Object{{"schema_version", 1}, {"plan_sha256", roles_.front().plan},
        {"roles", std::move(rows)}};
}
}
