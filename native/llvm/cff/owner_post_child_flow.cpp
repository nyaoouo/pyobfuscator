#include "owner_post_child_flow.hpp"
#include "owner_post_mixed_child_flow.hpp"
#include "bootstrap/handoff.hpp"
#include "bootstrap/post_handoff.hpp"
#include "measurement/observer.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

#include <array>
#include <cstddef>
#include <map>
#include <optional>
#include <queue>
#include <tuple>
#include <utility>
#include <vector>

namespace pyobfuscator::native::cff {
namespace {
constexpr auto entry_name = "pyobf_demo_post_payload";
constexpr auto wrapper_name = "pyobf_demo_protection_wrapper";
constexpr auto compute_name = "pyobf_demo_bound_compute";
constexpr auto query_name = "pyobf_native_measured_contribution_word_v1";

[[noreturn]] void reject(const char *reason) {
    llvm::report_fatal_error(llvm::Twine("post child flow: ") + reason);
}

const llvm::Value *local_value(const llvm::Value *value, unsigned depth = 0) {
    if (depth == 16) reject("local pointer chain is unbounded");
    const auto *read = llvm::dyn_cast<llvm::LoadInst>(value);
    const auto *slot = read == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(read->getPointerOperand()->stripPointerCasts());
    if (slot == nullptr || !read->getType()->isPointerTy()) return value;
    const llvm::StoreInst *write = nullptr;
    for (const auto *user : slot->users()) {
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
            if (store->getPointerOperand()->stripPointerCasts() != slot || write != nullptr || !store->isSimple())
                reject("local pointer slot has ambiguous writes");
            write = store;
        } else if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(user)) {
            if (load->getPointerOperand()->stripPointerCasts() != slot || !load->isSimple())
                reject("local pointer slot has an ambiguous read");
        } else if (!llvm::isa<llvm::LifetimeIntrinsic>(user)) {
            reject("local pointer slot escapes its body");
        }
    }
    if (write == nullptr) reject("local pointer slot has no source");
    return local_value(write->getValueOperand(), depth + 1);
}

bool constant_index(const llvm::Value *value, std::uint64_t expected) {
    const auto *number = llvm::dyn_cast<llvm::ConstantInt>(value);
    return number != nullptr && number->getZExtValue() == expected;
}

bool struct_field(const llvm::Value *value, llvm::StringRef type, unsigned field, const llvm::Value *&base) {
    const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(value);
    const auto *record = gep == nullptr ? nullptr : llvm::dyn_cast<llvm::StructType>(gep->getSourceElementType());
    if (record == nullptr || !record->hasName() || !record->getName().contains(type) ||
            gep->getNumIndices() != 2 || !constant_index(gep->getOperand(1), 0) ||
            !constant_index(gep->getOperand(2), field)) return false;
    base = local_value(gep->getPointerOperand());
    return true;
}

// Source O2 erases the named structs; resolve only the authored layout and a unique local spill.
bool byte_field(const llvm::Value *value, const llvm::Value *base, std::uint64_t offset) {
    const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(value);
    return gep != nullptr && gep->isInBounds() && gep->getSourceElementType()->isIntegerTy(8) &&
        gep->getNumIndices() == 1 && gep->getPointerOperand() == base &&
        constant_index(gep->getOperand(1), offset);
}

bool post_pointer(const llvm::Value *value, const llvm::Argument *handoff) {
    const auto *read = llvm::dyn_cast<llvm::LoadInst>(local_value(value));
    return read != nullptr && read->isSimple() && read->getType()->isPointerTy() &&
        byte_field(local_value(read->getPointerOperand()), handoff, offsetof(demo::PayloadHandoff, post));
}

std::uint64_t role_field_offset(unsigned field) {
    switch (field) {
    case 0: return offsetof(demo::PostRole, spec);
    case 1: return offsetof(demo::PostRole, observation);
    case 2: return offsetof(demo::PostRole, material);
    case 3: return offsetof(demo::PostRole, material_size);
    default: reject("unsupported post role field");
    }
}

int byte_role_field(const llvm::Value *value, const llvm::Argument *handoff, unsigned field) {
    const auto *resolved = local_value(value);
    const auto *read = llvm::dyn_cast<llvm::LoadInst>(resolved);
    const auto *pointer = read == nullptr ? resolved : local_value(read->getPointerOperand());
    const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(pointer);
    if (gep == nullptr || !post_pointer(gep->getPointerOperand(), handoff)) return -1;
    for (unsigned role = 0; role != 2; ++role)
        if (byte_field(gep, gep->getPointerOperand(),
                offsetof(demo::PostHandoff, roles) + role * sizeof(demo::PostRole) + role_field_offset(field)))
            return static_cast<int>(role);
    return -1;
}

int role_index(const llvm::Value *value, const llvm::Argument *handoff) {
    const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(local_value(value));
    const auto *array = gep == nullptr ? nullptr : llvm::dyn_cast<llvm::ArrayType>(gep->getSourceElementType());
    const auto *element = array == nullptr ? nullptr : llvm::dyn_cast<llvm::StructType>(array->getElementType());
    if (element == nullptr || !element->hasName() || !element->getName().contains("demo::PostRole") ||
            array->getNumElements() != 2 || gep->getNumIndices() != 2 ||
            !constant_index(gep->getOperand(1), 0)) return -1;
    const auto *index = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(2));
    const llvm::Value *post = nullptr, *input = nullptr;
    if (index == nullptr || index->getZExtValue() > 1 ||
            !struct_field(local_value(gep->getPointerOperand()), "demo::PostHandoff", 3, post)) return -1;
    const auto *post_load = llvm::dyn_cast<llvm::LoadInst>(post);
    if (post_load == nullptr || !struct_field(local_value(post_load->getPointerOperand()),
            "demo::PayloadHandoff", 7, input) || local_value(input) != handoff) return -1;
    return static_cast<int>(index->getZExtValue());
}

int role_field(const llvm::Value *value, const llvm::Argument *handoff, unsigned field) {
    const int byte_role = byte_role_field(value, handoff, field);
    if (byte_role >= 0) return byte_role;
    const auto *read = llvm::dyn_cast<llvm::LoadInst>(value);
    const llvm::Value *base = nullptr;
    if (!struct_field(local_value(read == nullptr ? value : read->getPointerOperand()),
            "demo::PostRole", field, base)) return -1;
    return role_index(base, handoff);
}

bool handoff_lease(const llvm::Value *value, const llvm::Argument *handoff) {
    const auto *read = llvm::dyn_cast<llvm::LoadInst>(value);
    const llvm::Value *base = nullptr;
    return read != nullptr && ((struct_field(read->getPointerOperand(), "demo::PayloadHandoff", 3, base) &&
        local_value(base) == handoff) ||
        byte_field(read->getPointerOperand(), handoff, offsetof(demo::PayloadHandoff, expected)));
}

bool post_fold(const llvm::Value *value, const llvm::Argument *handoff) {
    const auto *read = llvm::dyn_cast<llvm::LoadInst>(value);
    if (read != nullptr) {
        const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(read->getPointerOperand());
        if (gep != nullptr && post_pointer(gep->getPointerOperand(), handoff) &&
                byte_field(gep, gep->getPointerOperand(), offsetof(demo::PostHandoff, fold))) return true;
    }
    const llvm::Value *post = nullptr, *input = nullptr;
    const auto *post_load = read == nullptr || !struct_field(read->getPointerOperand(),
        "demo::PostHandoff", 2, post) ? nullptr : llvm::dyn_cast<llvm::LoadInst>(post);
    return post_load != nullptr && struct_field(post_load->getPointerOperand(),
        "demo::PayloadHandoff", 7, input) && local_value(input) == handoff;
}

const llvm::Function *called(const llvm::CallBase &call) {
    return llvm::dyn_cast<llvm::Function>(call.getCalledOperand()->stripPointerCastsAndAliases());
}

struct ScopePath {
    const llvm::Value *scope = nullptr;
    const llvm::Value *snapshot = nullptr;
    unsigned constructors = 0;
};

std::optional<bool> validation_condition(const llvm::Value *value,
        const llvm::BasicBlock *predecessor, unsigned errors,
        const std::map<const llvm::Value *, std::pair<unsigned, bool>> &tests, unsigned depth = 0) {
    if (depth == 8) reject("post validation condition is too deep");
    if (const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(value))
        return constant->isOne();
    if (const auto found = tests.find(value); found != tests.end())
        return ((errors & (1u << found->second.first)) != 0) == found->second.second;
    if (const auto *phi = llvm::dyn_cast<llvm::PHINode>(value)) {
        if (predecessor == nullptr || phi->getBasicBlockIndex(predecessor) < 0)
            reject("post validation PHI has no incoming edge");
        return validation_condition(phi->getIncomingValueForBlock(predecessor), predecessor,
            errors, tests, depth + 1);
    }
    return std::nullopt;
}

void check_validation_gate(const llvm::Function &function, const llvm::CallBase &forward,
        const std::map<const llvm::Value *, int> &observed) {
    std::map<const llvm::Value *, unsigned> outputs;
    std::map<const llvm::Value *, std::pair<unsigned, bool>> tests;
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (call == nullptr || called(*call) == nullptr ||
                !called(*call)->getName().contains("8Snapshot5checkEv")) continue;
        if (call->arg_size() != 2) reject("post snapshot validation ABI changed");
        const auto source = observed.find(call->getArgOperand(1));
        if (source == observed.end() || source->second < 0 ||
                !outputs.emplace(call->getArgOperand(0), source->second).second)
            reject("post validation result is not unique to its role");
    }
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto *comparison = llvm::dyn_cast<llvm::ICmpInst>(&instruction);
        if (comparison == nullptr || (comparison->getPredicate() != llvm::CmpInst::ICMP_NE &&
                comparison->getPredicate() != llvm::CmpInst::ICMP_EQ) ||
                !constant_index(comparison->getOperand(1), 0)) continue;
        const auto *read = llvm::dyn_cast<llvm::LoadInst>(comparison->getOperand(0));
        const llvm::Value *section = nullptr, *validation = nullptr;
        if (read == nullptr || !read->isSimple() || !read->getType()->isIntegerTy(32)) continue;
        if (offsetof(measurement::observer::Validation, error) +
                offsetof(measurement::observer::Error, code) == 0 &&
                outputs.count(read->getPointerOperand()) != 0) {
            validation = read->getPointerOperand();
        } else if (!struct_field(read->getPointerOperand(),
                "measurement::CodeSection", 0, section) ||
                !struct_field(section, "observer::Validation", 0, validation)) {
            continue;
        }
        const auto result = outputs.find(validation);
        if (result == outputs.end() || !tests.emplace(comparison,
                std::make_pair(result->second, comparison->getPredicate() == llvm::CmpInst::ICMP_NE)).second)
            reject("post validation branch is disconnected from its snapshot check");
    }
    if (outputs.size() != 2 || tests.size() != 2)
        reject("post validation needs one error comparison per role");
    for (unsigned errors = 0; errors != 4; ++errors) {
        using State = std::tuple<const llvm::BasicBlock *, const llvm::BasicBlock *, unsigned>;
        std::queue<State> pending;
        std::set<State> visited;
        pending.emplace(&function.getEntryBlock(), nullptr, 0);
        bool reached = false;
        while (!pending.empty()) {
            const auto [block, predecessor, seen] = pending.front();
            pending.pop();
            if (!visited.emplace(block, predecessor, seen).second) continue;
            unsigned executed = seen;
            for (const auto &instruction : *block) {
                if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
                    if (call->arg_size() >= 2 && called(*call) != nullptr &&
                            called(*call)->getName().contains("8Snapshot5checkEv")) {
                        const auto output = outputs.find(call->getArgOperand(0));
                        if (output != outputs.end()) executed |= 1u << output->second;
                    }
                    if (call == &forward) {
                        if (errors != 0 || executed != 3)
                            reject("post snapshot validation does not gate Scope");
                        reached = true;
                    }
                }
            }
            const auto *branch = llvm::dyn_cast<llvm::BranchInst>(block->getTerminator());
            if (branch && branch->isConditional()) {
                const auto choice = validation_condition(branch->getCondition(), predecessor, errors, tests);
                if (choice) {
                    pending.emplace(branch->getSuccessor(*choice ? 0 : 1), block, executed);
                    continue;
                }
            }
            for (unsigned index = 0; index != block->getTerminator()->getNumSuccessors(); ++index)
                pending.emplace(block->getTerminator()->getSuccessor(index), block, executed);
        }
        if (errors == 0 && !reached) reject("valid post snapshots cannot reach their consumer");
    }
}

void check_entry(const llvm::Function &function, const llvm::Function &wrapper, bool transformed, bool mixed,
        std::array<ScopePath, 2> &paths) {
    if (function.arg_size() != 2 || !function.getArg(0)->getType()->isPointerTy())
        reject("entry ABI is unsupported");
    std::map<const llvm::Value *, int> observed;
    std::map<const llvm::Value *, unsigned> checked;
    std::map<const llvm::Value *, const llvm::CallBase *> observation_calls;
    std::vector<const llvm::CallBase *> constructors;
    const llvm::CallBase *forward = nullptr;
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        const auto *target = call == nullptr ? nullptr : called(*call);
        if (target == nullptr) continue;
        const auto name = target->getName();
        if (name.contains("measurement8observer7observeE")) {
            if (call->arg_size() != 3) reject("observer source ABI changed");
            const int role = role_field(call->getArgOperand(1), function.getArg(0), 1);
            if (role < 0 || !observed.emplace(call->getArgOperand(0), role).second)
                reject("observer source is not one exact post role");
            observation_calls.emplace(call->getArgOperand(0), call);
        } else if (name.contains("8Snapshot5checkEv")) {
            if (call->arg_size() != 2 || ++checked[call->getArgOperand(1)] != 1)
                reject("post snapshot validation is ambiguous");
        } else if (name.contains("contribution6scoped5ScopeC1E") ||
                name.contains("contribution6scoped5ScopeC2E")) {
            constructors.push_back(call);
        } else if (target == &wrapper) {
            if (forward != nullptr || call->arg_size() != (mixed ? 5u : 4u))
                reject("post wrapper forwarding is ambiguous");
            forward = call;
        }
    }
    const llvm::DominatorTree dominators(const_cast<llvm::Function &>(function));
    for (const auto *call : constructors) {
        if (call->arg_size() != 7) reject("measured Scope constructor ABI changed");
        const int role = role_field(call->getArgOperand(2), function.getArg(0), 0);
        const auto observed_source = observed.find(call->getArgOperand(6));
        const auto validation = checked.find(call->getArgOperand(6));
        if (role < 0 || !handoff_lease(call->getArgOperand(1), function.getArg(0)) ||
                !post_fold(call->getArgOperand(3), function.getArg(0)) ||
                role_field(call->getArgOperand(4), function.getArg(0), 2) != role ||
                role_field(call->getArgOperand(5), function.getArg(0), 3) != role ||
                observed_source == observed.end() || observed_source->second != role ||
                validation == checked.end() || validation->second != 1 ||
                ++paths[role].constructors != 1)
            reject("Scope mixes post role, material or unchecked snapshot");
        if (!transformed && !dominators.dominates(observation_calls.find(call->getArgOperand(6))->second, call))
            reject("Scope is constructed before its role observation");
        paths[role].scope = call->getArgOperand(0);
        paths[role].snapshot = call->getArgOperand(6);
    }
    if (observed.size() != 2 || checked.size() != 2 || forward == nullptr)
        reject("post entry lacks two observed, checked role paths");
    for (unsigned role = 0; role != 2; ++role)
        if (paths[role].constructors != 1 || observed.find(paths[role].snapshot) == observed.end() ||
                observed.find(paths[role].snapshot)->second != static_cast<int>(role) ||
                local_value(forward->getArgOperand(role + unsigned(mixed))) != paths[role].scope)
            reject("post wrapper received the wrong role Scope");
    if (mixed && !handoff_lease(forward->getArgOperand(0), function.getArg(0)))
        reject("mixed post wrapper received a detached owned lease");
    if (!transformed) check_validation_gate(function, *forward, observed);
}

void check_wrapper(const llvm::Function &wrapper, const llvm::Function &compute, bool mixed) {
    if (wrapper.arg_size() != (mixed ? 5u : 4u) || compute.arg_size() != (mixed ? 3u : 2u))
        reject("post consumer ABI changed");
    unsigned calls = 0;
    for (const auto &block : wrapper) for (const auto &instruction : block)
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction); call != nullptr && called(*call) == &compute) {
            if (call->arg_size() != (mixed ? 3u : 2u) ||
                    local_value(call->getArgOperand(unsigned(mixed))) != wrapper.getArg(1 + unsigned(mixed)) ||
                    (mixed && local_value(call->getArgOperand(0)) != wrapper.getArg(0)))
                reject("compute received the wrong role Scope");
            ++calls;
        }
    if (calls != 1) reject("compute forwarding is missing or ambiguous");
}

void check_site(const llvm::Function &function, unsigned site) {
    unsigned matches = 0;
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (call == nullptr || called(*call) == nullptr || called(*call)->getName() != query_name ||
                call->arg_size() != 7 || !constant_index(call->getArgOperand(4), site)) continue;
        if (local_value(call->getArgOperand(0)) != function.getArg(0) ||
                call->getMetadata("pyobf.contribution.query") == nullptr) reject("post site lost its role Scope source");
        ++matches;
    }
    if (matches != 1) reject("post marker site is missing or duplicated");
}

void check(const llvm::Module &module, bool transformed, bool mixed) {
    const auto *entry = module.getFunction(entry_name);
    const auto *wrapper = module.getFunction(wrapper_name);
    const auto *compute = module.getFunction(compute_name);
    if (entry == nullptr || wrapper == nullptr || compute == nullptr ||
            entry->isDeclaration() || wrapper->isDeclaration() || compute->isDeclaration())
        reject("complete POST child definitions are required");
    std::array<ScopePath, 2> paths{};
    check_entry(*entry, *wrapper, transformed, mixed, paths);
    check_wrapper(*wrapper, *compute, mixed);
    if (transformed) {
        for (const auto *function : {entry, wrapper, compute})
            if (!function->hasFnAttribute("pyobf.cff.transformed")) reject("post consumer lost selected CFF");
        if (mixed) {
            verify_post_mixed_child_sites(*wrapper, 1);
            verify_post_mixed_child_sites(*compute, 1);
        } else {
            check_site(*wrapper, 702);
            check_site(*compute, 701);
        }
    }
}
}

PostChildSeal::PostChildSeal(const llvm::Module &module, const std::set<std::string> &selected, bool mixed)
    : mixed_(mixed) {
    const auto *entry = module.getFunction(entry_name);
    const auto *wrapper = module.getFunction(wrapper_name);
    const auto *compute = module.getFunction(compute_name);
    if (entry == nullptr && wrapper == nullptr) return;
    if (entry == nullptr || wrapper == nullptr || compute == nullptr ||
            !selected.count(entry_name) || !selected.count(wrapper_name) || !selected.count(compute_name))
        reject("POST child requires three selected functions");
    check(module, false, mixed_);
    active_ = true;
}

void verify_post_child_source(const llvm::Module &module) {
    if (module.getFunction(entry_name) != nullptr || module.getFunction(wrapper_name) != nullptr) {
        const auto *compute = module.getFunction(compute_name);
        check(module, false, compute != nullptr && compute->arg_size() == 3);
    }
}

void verify_post_child(const llvm::Module &module) {
    if (module.getFunction(entry_name) != nullptr || module.getFunction(wrapper_name) != nullptr) {
        const auto *compute = module.getFunction(compute_name);
        check(module, true, compute != nullptr && compute->arg_size() == 3);
    }
}

llvm::json::Object PostChildSeal::verify(const llvm::Module &module) const {
    if (!active_) reject("inactive POST child cannot claim role flow");
    check(module, true, mixed_);
    llvm::json::Array roles;
    for (unsigned role = 0; role != 2; ++role) roles.push_back(llvm::json::Object{
        {"role", role}, {"consumer", role == 0 ? wrapper_name : compute_name},
        {"site", mixed_ ? 0 : (role == 0 ? 702 : 701)},
        {"role_to_scope_verified", true}, {"scope_forwarding_verified", true},
        {"site_scope_binding_verified", true}});
    return llvm::json::Object{{"schema_version", mixed_ ? 2 : 1},
        {"scheme", mixed_ ? "post-mixed-scope-flow-v1" : "post-scope-flow-v1"},
        {"roles", std::move(roles)}};
}
}
