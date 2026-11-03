#include "transition_model.hpp"

#include <map>

#include "llvm/IR/Constants.h"
#include "llvm/IR/ConstantFolder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {
bool model_result(const llvm::Function &function, std::uint32_t state, bool predicate, const llvm::ConstantInt *literal = nullptr) {
    if (function.size() != 1 || function.arg_size() != 2) return false;
    struct Value { bool normal = false; llvm::Constant *constant = nullptr; };
    std::map<const llvm::Value *, Value> values;
    values[function.getArg(0)] = {true};
    const auto value = [&](const llvm::Value *operand) {
        if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(operand)) return Value{false, const_cast<llvm::ConstantInt *>(constant)};
        const auto found = values.find(operand); return found == values.end() ? Value{} : found->second;
    };
    for (const auto &instruction : function.getEntryBlock()) {
        if (instruction.hasPoisonGeneratingAnnotations()) return false;
        Value result;
        if (const auto *read = llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
            if (read->getPointerOperand() != function.getArg(1) || !read->getType()->isIntegerTy(32) ||
                    read->isAtomic() || read->getAlign().value() != 4) return false;
            result.constant = llvm::ConstantInt::get(read->getType(), state);
        } else if (const auto *op = llvm::dyn_cast<llvm::BinaryOperator>(&instruction)) {
            const auto left = value(op->getOperand(0)), right = value(op->getOperand(1));
            const bool width = literal != nullptr ? op->getType()->isIntegerTy() && op->getType()->getIntegerBitWidth() <= 128 :
                op->getType()->isIntegerTy(32) || op->getType()->isIntegerTy(1);
            if (!width ||
                    op->hasNoUnsignedWrap() || op->hasNoSignedWrap() || op->isExact()) return false;
            if (left.constant != nullptr && right.constant != nullptr)
                result.constant = llvm::ConstantExpr::get(op->getOpcode(), left.constant, right.constant);
            else {
                const auto identity = [&](Value symbolic, Value literal, bool right_side) {
                    const auto *number = llvm::dyn_cast_or_null<llvm::ConstantInt>(literal.constant);
                    if (!symbolic.normal || number == nullptr) return false;
                    switch (op->getOpcode()) {
                    case llvm::Instruction::Xor: case llvm::Instruction::Add: case llvm::Instruction::Or: return number->isZero();
                    case llvm::Instruction::Sub: return !right_side && number->isZero();
                    case llvm::Instruction::Mul: return number->isOne();
                    case llvm::Instruction::And: return number->isMinusOne();
                    default: return false;
                    }
                };
                result.normal = identity(left, right, false) || identity(right, left, true);
            }
        } else if (const auto *cast = llvm::dyn_cast<llvm::CastInst>(&instruction)) {
            if (literal == nullptr || !llvm::isa<llvm::TruncInst, llvm::ZExtInst>(cast) ||
                    !cast->getType()->isIntegerTy() || cast->getType()->getIntegerBitWidth() > 128 ||
                    !cast->getSrcTy()->isIntegerTy() || cast->getSrcTy()->getIntegerBitWidth() > 128) return false;
            const auto input = value(cast->getOperand(0));
            if (input.constant == nullptr) return false;
            result.constant = llvm::ConstantExpr::getCast(cast->getOpcode(), input.constant, cast->getType());
        } else if (const auto *compare = llvm::dyn_cast<llvm::ICmpInst>(&instruction)) {
            const auto left = value(compare->getOperand(0)), right = value(compare->getOperand(1));
            if (left.constant != nullptr && right.constant != nullptr)
                result.constant = llvm::cast<llvm::Constant>(llvm::ConstantFolder().FoldCmp(compare->getPredicate(), left.constant, right.constant));
        } else if (const auto *choice = llvm::dyn_cast<llvm::SelectInst>(&instruction)) {
            const auto test = value(choice->getCondition());
            if (const auto *condition = llvm::dyn_cast_or_null<llvm::ConstantInt>(test.constant))
                result = value(condition->isZero() ? choice->getFalseValue() : choice->getTrueValue());
        } else if (const auto *returned = llvm::dyn_cast<llvm::ReturnInst>(&instruction)) {
            const auto result = value(returned->getReturnValue());
            const auto *constant = llvm::dyn_cast_or_null<llvm::ConstantInt>(result.constant);
            if (literal != nullptr) return constant != nullptr && constant->getType() == literal->getType() && constant->getValue() == literal->getValue();
            return predicate ? constant != nullptr && constant->getType()->isIntegerTy(1) && constant->isOne() : result.normal;
        }
        else return false;
        if (result.constant != nullptr && !llvm::isa<llvm::ConstantInt>(result.constant)) return false;
        values[&instruction] = result;
    }
    return false;
}
}
bool transition_model_identity(const llvm::Function &function, std::uint32_t state) {
    return model_result(function, state, false);
}
bool transition_predicate_identity(const llvm::Function &function, std::uint32_t state) {
    return model_result(function, state, true);
}
bool transition_literal_identity(const llvm::Function &function, std::uint32_t state, const llvm::ConstantInt &literal) {
    if (literal.getBitWidth() > 128) return false;
    return model_result(function, state, false, &literal);
}
}
