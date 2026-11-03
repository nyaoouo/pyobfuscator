#include "contribution_expression.hpp"
#include "contribution_mix.hpp"
#include "transition_encode.hpp"
#include "contribution/value.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

namespace {
constexpr std::uint32_t reference(unsigned index) {
    using namespace pyobfuscator::native::contribution;
    auto state = initialize(0x50594f42u, 0x1000u + index, 0x2000u + index);
    state = source(state, 0xa100u + index, 0x2001, 3);
    for (auto value : {0x1234abcdu, 0x9876ef01u ^ index, 0xffffffffu - index}) state = word(state, value);
    state = source(state, 0xb100u + index, 0x1001, 2);
    for (auto value : {0u, 0x80000000u + index}) state = word(state, value);
    return finish(state);
}
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 1;
    llvm::LLVMContext context;
    llvm::Module module("native-contribution-correction-v1", context);
    auto *word = llvm::Type::getInt32Ty(context);
    for (unsigned index = 0; index != 3; ++index) {
        auto *function = llvm::Function::Create(llvm::FunctionType::get(word, {word, word}, false),
            llvm::Function::ExternalLinkage, "contribution_delta_" + std::to_string(index), module);
        llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", function));
        function->getArg(0)->setName("current"); function->getArg(1)->setName("observed");
        const auto current = 0x13579bdfu + index * 0x10203u;
        const auto target = 0x2468ace0u ^ (index * 0x9e37u);
        const auto contribution_salt = 0x73a92e11u + index * 17;
        const auto transition_salt = 0x5a91c37du ^ (index * 0x101u);
        using namespace pyobfuscator::native;
        const auto sealed = contribution::seal(cff::encode_delta(current, target, transition_salt), reference(index), contribution_salt);
        llvm::Value *state = function->getArg(0), *observed = function->getArg(1);
        if (argc == 3) {
            if (llvm::StringRef(argv[2]) == "invalid-state") state = builder.getInt64(1);
            else if (llvm::StringRef(argv[2]) == "invalid-observation") observed = builder.getInt64(1);
            else if (llvm::StringRef(argv[2]) == "null-observation") observed = nullptr;
            else return 5;
        }
        builder.CreateRet(cff::emit_contribution_delta(builder, state, observed, sealed, contribution_salt, transition_salt));
    }
    using namespace pyobfuscator::native::cff;
    for (unsigned count = 1; count <= 3; ++count) {
        auto *function = llvm::Function::Create(llvm::FunctionType::get(word, {word, word, word}, false),
            llvm::Function::ExternalLinkage, "contribution_mix_" + std::to_string(count), module);
        llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", function));
        std::vector<std::pair<std::uint32_t, std::uint32_t>> labels;
        std::vector<llvm::Value *> inputs;
        std::vector<const llvm::Value *> leaves;
        for (unsigned index = 0; index != count; ++index) {
            labels.push_back({17 + index * 12, 1}); inputs.push_back(function->getArg(index)); leaves.push_back(inputs.back());
        }
        const auto plan = plan_contribution_mix(77, 13, 101, labels);
        auto *actual = emit_contribution_mix(builder, plan, inputs); builder.CreateRet(actual);
        const auto &body = function->getEntryBlock();
        if (!match_contribution_mix(actual, plan, leaves, body)) return 6;
        for (unsigned part = 0; part != count; ++part) {
            auto changed = leaves; changed[part] = builder.getInt32(0);
            if (match_contribution_mix(actual, plan, changed, body)) return 7;
            auto tags = labels; tags[part].first ^= 1;
            if (match_contribution_mix(actual, plan_contribution_mix(77, 13, 101, tags), leaves, body)) return 8;
            tags = labels; tags[part].second ^= 1;
            if (match_contribution_mix(actual, plan_contribution_mix(77, 13, 101, tags), leaves, body)) return 9;
        }
        if (match_contribution_mix(actual, plan_contribution_mix(78, 13, 101, labels), leaves, body) ||
                match_contribution_mix(actual, plan_contribution_mix(77, 14, 101, labels), leaves, body) ||
                match_contribution_mix(actual, plan_contribution_mix(77, 13, 102, labels), leaves, body)) return 10;
        for (auto &instruction : function->getEntryBlock()) if (auto *op = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
                op != nullptr && op->getOpcode() == llvm::Instruction::Mul) {
            op->setHasNoUnsignedWrap(true);
            if (match_contribution_mix(actual, plan, leaves, body)) return 11;
            op->setHasNoUnsignedWrap(false); break;
        }
    }
    if (llvm::verifyModule(module, &llvm::errs())) return 2;
    std::error_code error;
    llvm::raw_fd_ostream output(argv[1], error, llvm::sys::fs::OF_Text);
    if (error) return 3;
    module.print(output, nullptr); output.flush();
    return output.has_error() ? 4 : 0;
}
