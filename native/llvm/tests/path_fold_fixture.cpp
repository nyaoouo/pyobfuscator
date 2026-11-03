#include "path_fold.hpp"
#include "path_fold/value.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 1;
    llvm::LLVMContext context;
    llvm::Module module("native-path-fold-v1", context);
    auto *word = llvm::Type::getInt32Ty(context);
    auto *pointer = llvm::PointerType::getUnqual(context);
    auto *nothing = llvm::Type::getVoidTy(context);
    auto make = [&](const char *name, llvm::Type *result, llvm::ArrayRef<llvm::Type *> arguments) {
        auto *function = llvm::Function::Create(llvm::FunctionType::get(result, arguments, false),
            llvm::Function::ExternalLinkage, name, module);
        llvm::BasicBlock::Create(context, "entry", function);
        return function;
    };
    using namespace pyobfuscator::native;
    auto *initial = make("fold_initial", nothing, {pointer, word});
    llvm::IRBuilder<> builder(&initial->getEntryBlock());
    if (argc == 3) {
        if (llvm::StringRef(argv[2]) == "invalid-storage") {
            cff::emit_path_fold_initialize(builder, builder.getInt32(0), builder.getInt32(1));
            return 7;
        }
        cff::emit_path_fold_initialize(builder, initial->getArg(0), builder.getInt64(1));
        return 6;
    }
    cff::emit_path_fold_initialize(builder, initial->getArg(0), initial->getArg(1));
    builder.CreateRetVoid();
    auto *step = make("fold_step", nothing, {pointer, word, word});
    builder.SetInsertPoint(&step->getEntryBlock());
    cff::emit_path_fold_advance(builder, step->getArg(0), step->getArg(1), step->getArg(2));
    builder.CreateRetVoid();
    auto *bound = make("fold_bound", word, {word});
    bound->getArg(0)->setName("current");
    builder.SetInsertPoint(&bound->getEntryBlock());
    constexpr auto encoded = path_fold::encode_word(0x13579bdfu, 0x2468ace0u, 0x5a91c37du);
    builder.CreateRet(cff::emit_path_fold_word(builder, bound->getArg(0), encoded, 0x5a91c37du));
    if (llvm::verifyModule(module, &llvm::errs())) return 2;
    std::error_code error;
    llvm::raw_fd_ostream output(argv[1], error, llvm::sys::fs::OF_Text);
    if (error) return 3;
    module.print(output, nullptr);
    output.flush();
    return output.has_error() ? 4 : 0;
}
