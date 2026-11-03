#include "path_fold.hpp"
#include "path_fold_sites.hpp"
#include "state_layout.hpp"
#include "path_fold/value.hpp"

#include <cstdio>

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

namespace {
bool check(bool advance, unsigned mutation) {
    using namespace pyobfuscator::native;
    llvm::LLVMContext context;
    llvm::Module module("fold-frozen-source", context);
    auto *pointer = llvm::PointerType::getUnqual(context);
    auto *nothing = llvm::Type::getVoidTy(context);
    auto *integer = llvm::Type::getInt32Ty(context);
    auto *owner = llvm::Function::Create(llvm::FunctionType::get(nothing, {pointer, pointer}, false),
        llvm::Function::ExternalLinkage, "owner", module);
    auto *entry = llvm::BasicBlock::Create(context, "entry", owner);
    auto *body = llvm::BasicBlock::Create(context, "body", owner);
    auto *dispatch = llvm::BasicBlock::Create(context, "dispatch", owner);
    llvm::IRBuilder<> builder(entry);
    auto *state = builder.CreateAlloca(integer);
    state->setMetadata("pyobf.path-fold.root", llvm::MDNode::get(context, {}));
    constexpr std::uint32_t expected_state = 0xa71935cbu, normal = 0x512c7a93u, tag = 0x3819u, salt = 0x871c591bu;
    builder.CreateStore(builder.getInt32(expected_state), state);
    builder.CreateBr(body);
    builder.SetInsertPoint(body);
    std::vector<llvm::Type *> parameters{pointer, integer};
    if (advance) parameters.push_back(integer);
    auto *marker = llvm::Function::Create(llvm::FunctionType::get(nothing, parameters, false),
        llvm::Function::ExternalLinkage, advance ? "pyobf_native_path_fold_step_v1" : "pyobf_native_path_fold_init_v1", module);
    marker->addFnAttr(llvm::Attribute::NoUnwind);
    std::vector<llvm::Value *> arguments{owner->getArg(0), builder.getInt32(advance ? tag : normal)};
    if (advance) arguments.push_back(builder.getInt32(normal));
    auto *call = builder.CreateCall(marker, arguments);
    call->setDoesNotThrow();
    call->addParamAttr(0, llvm::Attribute::NonNull);
    call->addParamAttr(0, llvm::Attribute::getWithAlignment(context, llvm::Align(4)));
    call->addParamAttr(0, llvm::Attribute::getWithDereferenceableBytes(context, 32));
    const auto id = llvm::MDString::get(context, "input.frozen.fold");
    call->setMetadata("pyobf.cff.site", llvm::MDNode::get(context, id));
    builder.CreateBr(dispatch);
    builder.SetInsertPoint(dispatch);
    auto *read = builder.CreateLoad(integer, state);
    read->setMetadata("pyobf.path-fold.dispatch", llvm::MDNode::get(context, {}));
    builder.CreateRetVoid();
    cff::StateLayout layout;
    layout.states[body] = expected_state;
    const cff::InstructionSite planned{call, 0, {}};
    cff::PathFoldSeal seal(*owner, layout, {planned});
    if (mutation != 4) {
        builder.SetInsertPoint(call);
        auto *current = builder.CreateLoad(integer, state);
        current->setVolatile(true);
        current->setMetadata("pyobf.path-fold.state", llvm::MDNode::get(context, id));
        const auto encoded = path_fold::encode_word(normal, expected_state, salt) ^ (mutation == 1 ? 1u : 0u);
        auto *word = cff::emit_path_fold_word(builder, current, encoded, salt);
        auto *storage = owner->getArg(mutation == 2 ? 1 : 0);
        const auto label = advance ? tag + (mutation == 3 ? 1u : 0u) : 0u;
        auto stores = advance ? cff::emit_path_fold_advance(builder, storage, builder.getInt32(label), word) :
                                cff::emit_path_fold_initialize(builder, storage, word);
        unsigned lane = 0;
        for (auto *instruction = current->getNextNode(); instruction != call; instruction = instruction->getNextNode())
            if (auto *load = llvm::dyn_cast<llvm::LoadInst>(instruction))
                load->setMetadata("pyobf.path-fold.before", llvm::MDNode::get(context, {
                    id, llvm::ConstantAsMetadata::get(builder.getInt32(lane++))}));
        for (unsigned index = 0; index != 8; ++index)
            stores[index]->setMetadata("pyobf.path-fold.bound", llvm::MDNode::get(context, {
                id, llvm::ConstantAsMetadata::get(builder.getInt32(1)),
                llvm::ConstantAsMetadata::get(builder.getInt32(advance ? 1 : 0)),
                llvm::ConstantAsMetadata::get(builder.getInt32(index)),
                llvm::ConstantAsMetadata::get(builder.getInt32(label)),
                llvm::ConstantAsMetadata::get(builder.getInt32(encoded)),
                llvm::ConstantAsMetadata::get(builder.getInt32(salt))}));
        owner->addFnAttr("pyobf.path-fold.bound");
    }
    call->eraseFromParent();
    if (llvm::verifyModule(module, &llvm::errs())) return false;
    // These coherent edits pass the expression-only proof. The independent frozen
    // source plan must still reject changed material, storage, labels and missing sites.
    if (!cff::validate_path_fold(*owner).empty()) return false;
    return seal.verify(*owner).empty() == (mutation == 0);
}
}

int main() {
    for (bool advance : {false, true})
        for (unsigned mutation = 0; mutation != 5; ++mutation) {
            if (!advance && mutation == 3) continue;
            if (!check(advance, mutation)) {
                std::fprintf(stderr, "frozen fold source failed: advance=%u mutation=%u\n", static_cast<unsigned>(advance), mutation);
                return 1;
            }
        }
    std::puts("frozen path-fold source and coherent data/storage/label/loss mutations verified");
}
