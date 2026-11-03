#include "junk_expression.hpp"
#include "opaque_expression.hpp"

#include <cstdint>
#include <vector>

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    llvm::LLVMContext context;
    llvm::Module module("native-expression-contract", context);
    auto *integer = llvm::Type::getInt32Ty(context);
    auto *type = llvm::FunctionType::get(integer, {integer}, false);
    const std::uint32_t salt = 0xc137a95du;
    for (unsigned family = 0; family < 3; ++family) {
        auto *function = llvm::Function::Create(type, llvm::Function::ExternalLinkage,
            "opaque_" + std::to_string(family), module);
        function->getArg(0)->setName("input");
        auto *entry = llvm::BasicBlock::Create(context, "entry", function);
        llvm::IRBuilder<> builder(entry);
        auto *state = builder.CreateAlloca(integer, nullptr, "state");
        builder.CreateStore(function->getArg(0), state);
        auto *predicate = pyobfuscator::native::cff::emit_opaque_true(builder, state, salt, family);
        builder.CreateRet(builder.CreateZExt(predicate, integer));
    }
    for (unsigned rounds = 1; rounds <= 8; ++rounds) {
        auto *function = llvm::Function::Create(type, llvm::Function::ExternalLinkage,
            "junk_" + std::to_string(rounds), module);
        auto *entry = llvm::BasicBlock::Create(context, "entry", function);
        llvm::IRBuilder<> builder(entry);
        builder.CreateRet(pyobfuscator::native::cff::emit_junk_mix(builder, function->getArg(0), salt, rounds));
    }
    std::error_code error;
    llvm::raw_fd_ostream ir(argv[1], error, llvm::sys::fs::OF_Text);
    if (error) return 2;
    module.print(ir, nullptr);
    ir.flush();
    if (ir.has_error()) return 3;
    std::vector<std::uint32_t> values{0u, 1u, 2u, 3u, 0x7fffffffu, 0x80000000u,
                                      0xfffffffeu, 0xffffffffu, 0x55555555u, 0xaaaaaaaau};
    std::uint32_t random = 0x12345678u;
    for (unsigned index = 0; index < 2048; ++index) {
        random = random * 1664525u + 1013904223u;
        values.push_back(random);
    }
    llvm::json::Array vectors;
    for (const auto value : values) {
        llvm::json::Object row;
        row["input"] = value;
        llvm::json::Array expected;
        for (unsigned rounds = 1; rounds <= 8; ++rounds)
            expected.push_back(static_cast<std::int64_t>(
                pyobfuscator::native::cff::junk_mix_value(value, salt, rounds)));
        row["junk"] = std::move(expected);
        vectors.push_back(std::move(row));
    }
    llvm::raw_fd_ostream output(argv[2], error, llvm::sys::fs::OF_Text);
    if (error) return 4;
    output << llvm::json::Value(std::move(vectors)) << '\n';
    output.flush();
    return output.has_error() ? 5 : 0;
}
