#include "plan.hpp"
#include "source_report.hpp"
#include "control_operands.hpp"
#include "../cff/source_marker.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::archive {
namespace {

[[noreturn]] void invalid(const std::string &reason) {
    llvm::report_fatal_error(llvm::StringRef("native archive plan: " + reason));
}

void referenced_globals(llvm::Constant &root, std::set<llvm::GlobalVariable *> &globals) {
    llvm::SmallVector<llvm::Constant *, 16> pending{&root};
    llvm::SmallPtrSet<llvm::Constant *, 32> visited;
    while (!pending.empty()) {
        auto *value = pending.pop_back_val();
        if (!visited.insert(value).second) continue;
        if (auto *global = llvm::dyn_cast<llvm::GlobalVariable>(value)) {
            if (global->isConstant()) globals.insert(global);
        } else if (auto *alias = llvm::dyn_cast<llvm::GlobalAlias>(value)) {
            pending.push_back(alias->getAliasee());
        } else if (!llvm::isa<llvm::GlobalValue>(value)) {
            for (const auto &operand : value->operands())
                if (auto *constant = llvm::dyn_cast<llvm::Constant>(operand.get())) pending.push_back(constant);
        }
    }
}

bool literal_operand(const llvm::Instruction &instruction, unsigned index) {
    if (control_operand(instruction, index)) return false;
    if (llvm::isa<llvm::GetElementPtrInst>(instruction) || llvm::isa<llvm::AllocaInst>(instruction) ||
        llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) return false;
    if (llvm::isa<llvm::SwitchInst>(instruction)) return index == 0;
    if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
        if (call->isInlineAsm()) return false;
        // Keep closed source descriptors literal for their later compiler consumers.
        if (const auto *callee = call->getCalledFunction();
            callee != nullptr && cff::source_marker_name(callee->getName())) return false;
        if (const auto *callee = call->getCalledFunction();
            callee != nullptr && callee->getIntrinsicID() == llvm::Intrinsic::is_constant) return false;
        return index < call->arg_size() && !call->paramHasAttr(index, llvm::Attribute::ImmArg);
    }
    return true;
}

bool literal_value(const llvm::Constant &constant) {
    return llvm::isa<llvm::ConstantInt>(constant) || llvm::isa<llvm::ConstantFP>(constant) ||
           llvm::isa<llvm::ConstantAggregate>(constant) || llvm::isa<llvm::ConstantAggregateZero>(constant) ||
           llvm::isa<llvm::ConstantDataSequential>(constant);
}

struct Budget {
    std::uint64_t count = 0, total = 40, gates = 0;
    void admit(const PlannedRecord &record) {
        if (++count > 65536) invalid("record count exceeds 65536");
        total += 96 + record.bytes.size();
        gates += record.uses.size();
        if (total > 64 * 1024 * 1024) invalid("pool exceeds 64 MiB");
        if (gates > 262144) invalid("acquisition sites exceed 262144");
    }
};

}  // namespace

std::vector<PlannedRecord> analyze_uses(llvm::Module &module,
                                        const std::set<std::string> &functions,
                                        const std::set<std::string> &integer_exempt) {
    std::set<llvm::GlobalVariable *> globals;
    bool assembly = !module.getModuleInlineAsm().empty();
    for (auto &function : module) for (auto &block : function) for (auto &instruction : block) {
        if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) assembly |= call->isInlineAsm();
        if (!functions.count(function.getName().str()) || llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) continue;
        for (unsigned index = 0; index < instruction.getNumOperands(); ++index)
            if (!control_operand(instruction, index))
                if (auto *constant = llvm::dyn_cast<llvm::Constant>(instruction.getOperand(index))) referenced_globals(*constant, globals);
    }
    if (!globals.empty() && assembly) invalid("inline/module assembly prevents a closed global-use proof");
    const auto early = early_functions(module);
    std::vector<PlannedRecord> records;
    std::set<std::string> global_users;
    Budget budget;
    for (auto &global : module.globals()) {
        if (!globals.count(&global)) continue;
        PlannedRecord record;
        if (const auto reason = closed_global_uses(global, functions, record.uses); !reason.empty()) invalid(reason);
        if (const auto reason = encode_storage(*global.getInitializer(), module.getDataLayout(), record);
            !reason.empty()) invalid(reason);
        record.storage = &global;
        if (global.getAlign()) record.alignment = static_cast<unsigned>(global.getAlign()->value());
        if (record.alignment > 4096) invalid("global alignment exceeds 4096");
        record.id = "record-" + std::to_string(records.size());
        for (const auto &use : record.uses) global_users.insert(use.instruction->getFunction()->getName().str());
        budget.admit(record);
        records.push_back(std::move(record));
    }
    for (auto &function : module) {
        if (!functions.count(function.getName().str())) continue;
        const auto before = records.size();
        for (auto &block : function) for (auto &instruction : block) {
            for (unsigned index = 0; index < instruction.getNumOperands(); ++index) {
                auto *constant = llvm::dyn_cast<llvm::Constant>(instruction.getOperand(index));
                if (constant == nullptr || !literal_value(*constant) || !literal_operand(instruction, index)) continue;
                if (llvm::isa<llvm::ConstantInt>(constant) && integer_exempt.count(function.getName().str())) continue;
                PlannedRecord record;
                if (const auto reason = encode_storage(*constant, module.getDataLayout(), record); !reason.empty())
                    invalid(reason);
                record.id = "record-" + std::to_string(records.size());
                record.uses.push_back({&instruction, index});
                budget.admit(record);
                records.push_back(std::move(record));
            }
        }
        if ((before != records.size() || global_users.count(function.getName().str())) && early.count(function.getName().str()))
            invalid("archive acquisition is reachable from a constructor, destructor or loader entry");
    }
    return records;
}

std::vector<cff::InstructionSite> source_candidates(llvm::Function &function, bool integers) {
    std::vector<cff::InstructionSite> result;
    for (auto &block : function) for (auto &instruction : block) {
        for (unsigned index = 0; index < instruction.getNumOperands(); ++index) {
            if (control_operand(instruction, index)) continue;
            auto *constant = llvm::dyn_cast<llvm::Constant>(instruction.getOperand(index));
            if (constant == nullptr) continue;
            std::set<llvm::GlobalVariable *> globals;
            referenced_globals(*constant, globals);
            if (!globals.empty() || (literal_value(*constant) && literal_operand(instruction, index) &&
                (integers || !llvm::isa<llvm::ConstantInt>(constant))))
                result.push_back({&instruction, index, "constant-archive needs a materialized compiler plan"});
        }
    }
    return result;
}

}  // namespace pyobfuscator::native::archive
