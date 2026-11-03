#include "owner_post_mixed_child_flow.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/ErrorHandling.h"

#include <cstdint>
#include <map>
#include <set>

namespace pyobfuscator::native::cff {
namespace {
[[noreturn]] void reject(const char *reason) {
    llvm::report_fatal_error(llvm::Twine("mixed POST child flow: ") + reason);
}

const llvm::Value *local_pointer(const llvm::Value *value, unsigned depth = 0) {
    if (depth == 16) reject("pointer spill chain is unbounded");
    const auto *read = llvm::dyn_cast<llvm::LoadInst>(value);
    const auto *slot = read == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(
        read->getPointerOperand()->stripPointerCasts());
    if (slot == nullptr || !read->getType()->isPointerTy()) return value;
    const llvm::StoreInst *write = nullptr;
    for (const auto *user : slot->users()) {
        if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(user)) {
            if (store->getPointerOperand()->stripPointerCasts() != slot || write != nullptr || !store->isSimple())
                reject("ambiguous pointer spill");
            write = store;
        } else if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(user)) {
            if (load->getPointerOperand()->stripPointerCasts() != slot || !load->isSimple())
                reject("ambiguous pointer spill read");
        } else if (!llvm::isa<llvm::LifetimeIntrinsic>(user)) {
            reject("pointer spill escapes owner");
        }
    }
    if (write == nullptr) reject("pointer spill has no source");
    return local_pointer(write->getValueOperand(), depth + 1);
}

bool number(const llvm::Value *value, std::uint32_t &result) {
    const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(value);
    if (constant == nullptr || !constant->getType()->isIntegerTy(32)) return false;
    result = static_cast<std::uint32_t>(constant->getZExtValue());
    return result != 0;
}
}

void verify_post_mixed_child_sites(const llvm::Function &function, unsigned scope_argument) {
    if (function.arg_size() <= scope_argument || scope_argument == 0 ||
            !function.getArg(0)->getType()->isPointerTy() ||
            !function.getArg(scope_argument)->getType()->isPointerTy())
        reject("owner has no separate owned lease and measured Scope arguments");
    struct Counts { unsigned owned = 0, measured = 0, queries = 0; };
    std::map<std::uint32_t, Counts> sites;
    for (const auto &block : function) for (const auto &instruction : block) {
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        const auto *target = call == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(
            call->getCalledOperand()->stripPointerCastsAndAliases());
        if (target == nullptr) continue;
        const bool owned = target->getName() == "pyobf_native_mixed_owned_contribution_word_v1";
        const bool measured = target->getName() == "pyobf_native_mixed_measured_contribution_word_v1";
        if (!owned && !measured) continue;
        std::uint32_t site = 0, source = 0;
        if (call->arg_size() != 8 || !number(call->getArgOperand(4), site) ||
                !number(call->getArgOperand(5), source) ||
                local_pointer(call->getArgOperand(owned ? 0 : 7)) != function.getArg(0) ||
                local_pointer(call->getArgOperand(owned ? 7 : 0)) != function.getArg(scope_argument) ||
                call->getMetadata("pyobf.contribution.source") == nullptr)
            reject("query lost exact lease/Scope argument or source provenance");
        auto &count = sites[site];
        ++(owned ? count.owned : count.measured);
        count.queries += call->getMetadata("pyobf.contribution.query") != nullptr;
    }
    if (sites.size() < 3 || sites.size() > 8)
        reject("owner lacks three to eight bound original-edge sites");
    for (const auto &[site, count] : sites)
        if (site == 0 || count.owned == 0 || count.measured != 1 || count.queries != 1)
            reject("site lacks one measured and distinct owned query group");
}
}
