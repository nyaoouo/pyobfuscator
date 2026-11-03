#include "mutation_guard.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::cff {

CfgSeal::CfgSeal(const llvm::Function &function) {
    if (const auto *module = function.getParent())
        for (const auto &definition : *module)
            if (!definition.isDeclaration()) definitions_.push_back(&definition);
    for (const auto &block : function) {
        Block record{&block, block.getTerminator(), {}};
        if (record.terminator != nullptr)
            for (unsigned i = 0; i < record.terminator->getNumSuccessors(); ++i)
                record.successors.push_back(record.terminator->getSuccessor(i));
        blocks_.push_back(std::move(record));
    }
}

std::string CfgSeal::check_definitions(const llvm::Function &function) const {
    std::vector<const llvm::Function *> definitions;
    if (const auto *module = function.getParent())
        for (const auto &definition : *module)
            if (!definition.isDeclaration()) definitions.push_back(&definition);
    return definitions != definitions_ ? "component changed the sealed function-definition set" : "";
}

std::string CfgSeal::check(const llvm::Function &function) const {
    if (const auto reason = check_definitions(function); !reason.empty()) return reason;
    if (function.size() != blocks_.size()) return "component changed the sealed block set";
    unsigned position = 0;
    for (const auto &block : function) {
        const auto &expected = blocks_[position++];
        const auto *term = block.getTerminator();
        if (&block != expected.identity || term != expected.terminator)
            return "component replaced a sealed block or terminator";
        if (term == nullptr) continue;
        if (term->getNumSuccessors() != expected.successors.size())
            return "component changed the sealed successor count";
        for (unsigned i = 0; i < term->getNumSuccessors(); ++i)
            if (term->getSuccessor(i) != expected.successors[i])
                return "component changed a sealed edge";
    }
    return {};
}

}  // namespace pyobfuscator::native::cff
