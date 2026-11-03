#include "reference_routes.hpp"
#include "import_routes.hpp"

#include <map>
#include <set>
#include <vector>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
namespace {
constexpr const char *tags[]{"pyobf.ref.table", "pyobf.ref.initializer", "pyobf.ref.pending", "pyobf.ref.bound",
    "pyobf.ref.state", "pyobf.ref.state-slot", "pyobf.ref.control", "pyobf.ref.layout"};

std::optional<std::uint32_t> number(const llvm::MDNode *node, unsigned position) {
    const auto *integer = node == nullptr || position >= node->getNumOperands() ? nullptr :
        llvm::mdconst::dyn_extract<llvm::ConstantInt>(node->getOperand(position));
    if (integer == nullptr || !integer->getType()->isIntegerTy(32)) return {};
    return static_cast<std::uint32_t>(integer->getZExtValue());
}

bool flag(const llvm::Instruction &instruction, const char *name) {
    const auto *node = instruction.getMetadata(name);
    return node != nullptr && node->getNumOperands() == 0;
}

}  // namespace

std::optional<std::vector<const llvm::Function *>> reference_table_targets(const llvm::AllocaInst *table) {
    const auto *array = table == nullptr ? nullptr : llvm::dyn_cast<llvm::ArrayType>(table->getAllocatedType());
    const auto *count = table == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(table->getArraySize());
    if (array == nullptr || !array->getElementType()->isPointerTy() ||
        array->getElementType()->getPointerAddressSpace() != 0 || table->getAddressSpace() != 0 ||
        count == nullptr || !count->isOne() || table->getParent() != &table->getFunction()->getEntryBlock() ||
        array->getNumElements() < 2 || array->getNumElements() > 4096 ||
        (array->getNumElements() & (array->getNumElements() - 1))) return {};
    const auto *tag = table->getMetadata("pyobf.ref.table");
    const auto *profile = tag != nullptr && tag->getNumOperands() == 2 ? llvm::dyn_cast<llvm::MDString>(tag->getOperand(1)) : nullptr;
    const bool imported = profile != nullptr && profile->getString() == "import-routes";
    const auto *layout = table->getMetadata("pyobf.ref.layout");
    if (tag == nullptr || tag->getNumOperands() != (imported ? 2u : 1u) || number(tag, 0) != array->getNumElements() ||
        (imported && (layout == nullptr || layout->getNumOperands() != array->getNumElements()))) return {};
    std::vector<const llvm::Function *> values(array->getNumElements(), nullptr);
    std::set<unsigned> initialized;
    for (const auto *user : table->users()) {
        const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(user);
        if (gep == nullptr || gep->getPointerOperand() != table || gep->getFunction() != table->getFunction() ||
            gep->getSourceElementType() != array || gep->getNumIndices() != 2) return {};
        const auto *zero = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
        if (zero == nullptr || !zero->isZero()) return {};
        if (!flag(*gep, "pyobf.ref.initializer")) {
            if (gep->getMetadata("pyobf.ref.bound") == nullptr) return {};
            continue;
        }
        const auto *index = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(2));
        const auto *store = !gep->hasOneUse() ? nullptr : llvm::dyn_cast<llvm::StoreInst>(*gep->user_begin());
        if (index == nullptr || index->getValue().uge(values.size()) || store == nullptr || !store->isVolatile() ||
            store->isAtomic() ||
            store->getPointerOperand() != gep || !flag(*store, "pyobf.ref.initializer") ||
            store->getParent() != &table->getFunction()->getEntryBlock() ||
            !initialized.insert(static_cast<unsigned>(index->getZExtValue())).second) return {};
        const auto *target = llvm::dyn_cast<llvm::Function>(store->getValueOperand());
        if (target == nullptr && !llvm::isa<llvm::ConstantPointerNull>(store->getValueOperand())) return {};
        if (target != nullptr && (target->isDeclaration() != imported || target->isIntrinsic() ||
            target->hasAvailableExternallyLinkage() || target->getAddressSpace() != 0 ||
            (imported && !target->hasExternalLinkage()))) return {};
        if (imported) {
            const auto *planned = llvm::dyn_cast<llvm::ValueAsMetadata>(layout->getOperand(index->getZExtValue()));
            if (planned == nullptr || planned->getValue() != store->getValueOperand() ||
                store->getAlign() != table->getAlign()) return {};
        }
        values[index->getZExtValue()] = target;
    }
    if (initialized.size() != values.size()) return {};
    return values;
}

namespace {

struct Evaluator {
    const llvm::BasicBlock *body;
    std::uint32_t expected_state;
    const llvm::AllocaInst *state_slot = nullptr;
    std::map<const llvm::Value *, std::optional<std::uint32_t>> memo;
    std::set<const llvm::Value *> active;

    std::optional<std::uint32_t> evaluate(const llvm::Value *value, unsigned depth = 0) {
        if (depth > 32 || memo.size() > 256 || !value->getType()->isIntegerTy(32)) return {};
        if (const auto found = memo.find(value); found != memo.end()) return found->second;
        if (!active.insert(value).second) return {};
        std::optional<std::uint32_t> result;
        if (const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(value)) result = static_cast<std::uint32_t>(constant->getZExtValue());
        else if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(value)) {
            const auto *slot = llvm::dyn_cast<llvm::AllocaInst>(load->getPointerOperand());
            const auto *state = load->getMetadata("pyobf.ref.state");
            if (load->getParent() == body && slot != nullptr && slot->getAllocatedType()->isIntegerTy(32) &&
                slot->getParent() == &body->getParent()->getEntryBlock() && flag(*slot, "pyobf.ref.state-slot") &&
                state != nullptr && state->getNumOperands() == 1 && number(state, 0) == expected_state &&
                (state_slot == nullptr || state_slot == slot)) { state_slot = slot; result = expected_state; }
        } else if (const auto *operation = llvm::dyn_cast<llvm::BinaryOperator>(value)) {
            if (operation->getParent() == body && !operation->hasNoSignedWrap() && !operation->hasNoUnsignedWrap() &&
                !operation->isExact()) {
                const auto left = evaluate(operation->getOperand(0), depth + 1), right = evaluate(operation->getOperand(1), depth + 1);
                if (left && right) switch (operation->getOpcode()) {
                case llvm::Instruction::Xor: result = *left ^ *right; break;
                case llvm::Instruction::Mul: result = *left * *right; break;
                case llvm::Instruction::And: result = *left & *right; break;
                case llvm::Instruction::LShr: if (*right < 32) result = *left >> *right; break;
                default: break;
                }
            }
        }
        active.erase(value);
        memo.emplace(value, result);
        return result;
    }
};

}  // namespace

std::optional<ReferenceInfo> reference_info(const llvm::MDNode *node, bool bound) {
    if (node == nullptr || node->getNumOperands() < 4) return {};
    const auto *profile = llvm::dyn_cast<llvm::MDString>(node->getOperand(node->getNumOperands() - 1));
    const bool imported = profile != nullptr && profile->getString() == "import-routes";
    if (node->getNumOperands() != (bound ? 5u : 4u) + imported) return {};
    const auto *value = llvm::dyn_cast<llvm::ValueAsMetadata>(node->getOperand(0));
    const auto *target = value == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(value->getValue());
    const auto slot = number(node, 1), salt = number(node, 2), state = bound ? number(node, 4) : std::optional<std::uint32_t>{0};
    const auto *role = llvm::dyn_cast<llvm::MDString>(node->getOperand(3));
    if (target == nullptr || target->isDeclaration() != imported || target->isIntrinsic() || target->hasAvailableExternallyLinkage() ||
        target->getAddressSpace() != 0 || (imported && !target->hasExternalLinkage()) ||
        !slot || !salt || !state ||
        role == nullptr || (role->getString() != "call-target" && role->getString() != "function-address")) return {};
    return ReferenceInfo{target, *slot, *salt, *state, role->getString() == "call-target", imported};
}

const llvm::Function *resolve_reference_target(const llvm::Value *value) {
    const auto *load = llvm::dyn_cast<llvm::LoadInst>(value);
    const auto *gep = load == nullptr ? nullptr : llvm::dyn_cast<llvm::GetElementPtrInst>(load->getPointerOperand());
    const auto info = gep == nullptr ? std::optional<ReferenceInfo>{} : reference_info(gep->getMetadata("pyobf.ref.bound"), true);
    const auto *table = gep == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(gep->getPointerOperand());
    if (info && info->imported) return resolve_import_route(load, gep, table, *info);
    if (!info || !load->isVolatile() || !load->getType()->isPointerTy() || load->getType()->getPointerAddressSpace() != 0 ||
        !gep->hasOneUse() || load->getParent() != gep->getParent() || gep->getNumIndices() != 2) return nullptr;
    const auto values = reference_table_targets(table);
    const auto *mask = llvm::dyn_cast<llvm::BinaryOperator>(gep->getOperand(2));
    const auto *limit = mask == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(mask->getOperand(1));
    if (!values || mask == nullptr || mask->getOpcode() != llvm::Instruction::And || limit == nullptr ||
        limit->getValue() != values->size() - 1) return nullptr;
    Evaluator evaluator{gep->getParent(), info->state};
    const auto slot = evaluator.evaluate(mask);
    if (!slot || evaluator.state_slot == nullptr || *slot >= values->size() || *slot != info->slot ||
        (*values)[*slot] != info->target) return nullptr;
    unsigned state_slots = 0;
    for (const auto &block : *load->getFunction()) for (const auto &instruction : block)
        if (instruction.getMetadata("pyobf.ref.state-slot") != nullptr) {
            if (&instruction != evaluator.state_slot) return nullptr;
            ++state_slots;
        }
    if (state_slots != 1) return nullptr;
    return (*values)[*slot];
}

std::string validate_reference_routes(const llvm::Function &function) {
    for (const auto *name : tags) if (function.getMetadata(name) != nullptr)
        return "reference route artifacts have an invalid function owner";
    for (const auto &block : function) for (const auto &instruction : block) {
        if (instruction.getMetadata("pyobf.ref.pending") != nullptr) return "reference route did not bind its pending index";
        if (instruction.getMetadata("pyobf.ref.table") != nullptr &&
            !reference_table_targets(llvm::dyn_cast<llvm::AllocaInst>(&instruction))) return "reference route table is mutable, incomplete or escaping";
        if (instruction.getMetadata("pyobf.ref.layout") != nullptr && instruction.getMetadata("pyobf.ref.table") == nullptr)
            return "reference route layout has no table owner";
        if (instruction.getMetadata("pyobf.ref.initializer") != nullptr) {
            const auto *address = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction);
            if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction))
                address = llvm::dyn_cast<llvm::GetElementPtrInst>(store->getPointerOperand());
            const auto *table = address == nullptr ? nullptr : llvm::dyn_cast<llvm::AllocaInst>(address->getPointerOperand());
            if (!flag(instruction, "pyobf.ref.initializer") || table == nullptr || table->getMetadata("pyobf.ref.table") == nullptr)
                return "reference route initializer has no declared table owner";
        }
        if (instruction.getMetadata("pyobf.ref.bound") != nullptr) {
            if (!instruction.hasOneUse() || resolve_reference_target(*instruction.user_begin()) == nullptr)
                return "reference route target does not match its actual table/index/state graph";
        }
    }
    return {};
}

void reject_reference_artifacts(const llvm::Module &module) {
    for (const auto *name : tags) if (module.getNamedMetadata(name) != nullptr)
        llvm::report_fatal_error("native reference routes: unfinished private route artifacts in source input");
    for (const auto &function : module) {
        for (const auto *name : tags) if (function.getMetadata(name) != nullptr)
            llvm::report_fatal_error("native reference routes: unfinished private route artifacts in source input");
        for (const auto &block : function) for (const auto &instruction : block)
            for (const auto *name : tags) if (instruction.getMetadata(name) != nullptr)
                llvm::report_fatal_error("native reference routes: unfinished private route artifacts in source input");
    }
}

void finish_reference_routes(llvm::Module &module) {
    for (auto &function : module) {
        if (const auto reason = validate_reference_routes(function); !reason.empty())
            llvm::report_fatal_error(llvm::StringRef(reason));
        for (auto &block : function) for (auto &instruction : block)
            for (const auto *name : tags) instruction.setMetadata(name, nullptr);
    }
}

}  // namespace pyobfuscator::native::cff
