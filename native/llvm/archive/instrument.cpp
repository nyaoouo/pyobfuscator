#include "plan.hpp"

#include "../cff/site_provenance.hpp"
#include "../cff/site_report.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <map>

namespace pyobfuscator::native::archive {
namespace {

llvm::MDNode *tag(llvm::LLVMContext &context, const PlannedRecord &record,
                    llvm::StringRef source, unsigned index) {
    return llvm::MDNode::get(context, {llvm::MDString::get(context, record.id),
        llvm::MDString::get(context, source), llvm::ConstantAsMetadata::get(
            llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), index))});
}

llvm::Instruction *insert_before(const UseSite &use) {
    if (const auto *phi = llvm::dyn_cast<llvm::PHINode>(use.instruction))
        return phi->getIncomingBlock(use.operand)->getTerminator();
    return use.instruction;
}

void invalidate_purity(llvm::Module &module) {
    // Inferred purity can propagate through callers and opaque function pointers. The
    // intermediate module must not promise that the added crypto/writes cannot occur.
    constexpr llvm::Attribute::AttrKind invalid[]{llvm::Attribute::Memory, llvm::Attribute::NoFree,
        llvm::Attribute::NoSync, llvm::Attribute::NoCallback, llvm::Attribute::Speculatable,
        llvm::Attribute::WillReturn, llvm::Attribute::MustProgress};
    for (auto &function : module) {
        if (function.isDeclaration()) continue;
        for (const auto attribute : invalid) function.removeFnAttr(attribute);
        for (auto &block : function) for (auto &instruction : block) {
            instruction.setMetadata(llvm::LLVMContext::MD_invariant_load, nullptr);
            instruction.setMetadata(llvm::LLVMContext::MD_invariant_group, nullptr);
            if (auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
                if (const auto *callee = call->getCalledFunction(); callee == nullptr || !callee->isIntrinsic())
                    for (const auto attribute : invalid) call->removeFnAttr(attribute);
        }
    }
}

}  // namespace

void instrument_plan(llvm::Module &module, std::vector<PlannedRecord> &records) {
    auto &context = module.getContext();
    auto *word = llvm::Type::getInt32Ty(context);
    auto *pointer = llvm::PointerType::getUnqual(context);
    auto *size_type = module.getDataLayout().getIntPtrType(context);
    auto *frame_type = llvm::ArrayType::get(word, 8);
    auto *gate_type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), {pointer, pointer, size_type}, false);
    auto *mapping = module.getOrInsertNamedMetadata("pyobf.archive.records");
    auto *sources = module.getOrInsertNamedMetadata("pyobf.archive.sources");
    if (records.empty()) return;
    std::map<const llvm::Instruction *, std::pair<std::string, unsigned>> locations;
    std::set<llvm::Function *> stamped;
    for (auto &record : records) for (const auto &use : record.uses)
        if (stamped.insert(use.instruction->getFunction()).second)
            cff::stamp_site_provenance(*use.instruction->getFunction(), "archive-source");
    for (auto *function : stamped) for (const auto &block : *function) {
        unsigned index = 0;
        for (const auto &instruction : block) locations.emplace(&instruction, std::make_pair(block.getName().str(), index++));
    }
    for (auto &record : records) {
        const bool replace_operand = record.storage == nullptr;
        if (replace_operand) {
            record.storage = new llvm::GlobalVariable(module, record.initializer->getType(), false,
                llvm::GlobalValue::PrivateLinkage, llvm::Constant::getNullValue(record.initializer->getType()),
                "__pyobf_archive_storage_" + record.id);
            record.storage->setAlignment(llvm::Align(record.alignment));
        } else {
            record.storage->setConstant(false);
            record.storage->setInitializer(llvm::Constant::getNullValue(record.storage->getValueType()));
        }
        auto *gate = llvm::Function::Create(gate_type, llvm::GlobalValue::ExternalLinkage,
            "__pyobf_archive_pending_" + record.id, module);
        gate->addFnAttr(llvm::Attribute::NoUnwind);
        gate->addFnAttr("pyobf.archive.pending");
        mapping->addOperand(llvm::MDNode::get(context, {llvm::MDString::get(context, record.id),
            llvm::ValueAsMetadata::get(record.storage), llvm::ValueAsMetadata::get(gate),
            llvm::MDString::get(context, record.kind), llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(word, record.bit_width)),
            llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(word, record.alignment)),
            llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(word, record.byte_order)),
            llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(size_type, record.bytes.size()))}));
        for (const auto &use : record.uses) {
            auto &function = *use.instruction->getFunction();
            function.addFnAttr("pyobf.archive.planned");
            const auto source = cff::instruction_site_id(*use.instruction, "constant-archive", use.operand);
            const auto debug = use.instruction->getDebugLoc();
            sources->addOperand(llvm::MDNode::get(context, {llvm::ValueAsMetadata::get(&function),
                llvm::MDString::get(context, record.id), llvm::MDString::get(context, source),
                llvm::MDString::get(context, locations.at(use.instruction).first),
                llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(word, locations.at(use.instruction).second)),
                llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(word, use.operand)),
                llvm::MDString::get(context, debug ? debug->getFilename() : llvm::StringRef{}),
                llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(word, debug ? debug.getLine() : 0)),
                llvm::ValueAsMetadata::get(record.storage),
                llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(size_type, record.bytes.size()))}));
            llvm::IRBuilder<> setup(&*function.getEntryBlock().getFirstInsertionPt());
            auto *frame = setup.CreateAlloca(frame_type, nullptr, "pyobf.archive.key-frame");
            frame->setAlignment(llvm::Align(4));
            llvm::IRBuilder<> builder(insert_before(use));
            builder.SetCurrentDebugLocation(use.instruction->getDebugLoc());
            for (unsigned lane = 0; lane < 8; ++lane) {
                auto *slot = builder.CreateInBoundsGEP(frame_type, frame, {builder.getInt32(0), builder.getInt32(lane)});
                auto *store = builder.CreateStore(builder.getInt32(0), slot, true);
                store->setMetadata("pyobf.archive.key-slot", tag(context, record, source, lane));
            }
            auto *call = builder.CreateCall(gate, {frame, record.storage,
                llvm::ConstantInt::get(size_type, record.bytes.size())});
            call->setMetadata("pyobf.archive.gate", tag(context, record, source, use.operand));
            for (unsigned lane = 0; lane < 8; ++lane) {
                auto *slot = builder.CreateInBoundsGEP(frame_type, frame, {builder.getInt32(0), builder.getInt32(lane)});
                auto *store = builder.CreateStore(builder.getInt32(0), slot, true);
                store->setMetadata("pyobf.archive.key-clear", tag(context, record, source, lane));
            }
            if (replace_operand) {
                auto *load = builder.CreateLoad(record.storage->getValueType(), record.storage, "pyobf.archive.value");
                load->setAlignment(llvm::Align(record.alignment));
                use.instruction->setOperand(use.operand, load);
            }
        }
    }
    invalidate_purity(module);
}

}  // namespace pyobfuscator::native::archive
