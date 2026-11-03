#include "bindings.hpp"
#include "empty_plan.hpp"
#include "metadata.hpp"

#include <map>
#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

namespace pyobfuscator::native::archive {
namespace {

std::uint64_t little(llvm::StringRef bytes, std::size_t offset, unsigned width) {
    if (offset > bytes.size() || width > bytes.size() - offset) invalid_binding("package metadata is truncated");
    std::uint64_t value = 0;
    for (unsigned index = 0; index < width; ++index)
        value |= std::uint64_t{static_cast<std::uint8_t>(bytes[offset + index])} << (index * 8);
    return value;
}

unsigned kind_number(llvm::StringRef name) {
    const llvm::StringRef kinds[]{"integer", "binary16", "bfloat16", "binary32", "binary64",
        "x87_80", "binary128", "bytes", "code_units8", "code_units16", "code_units32"};
    for (unsigned index = 0; index < 11; ++index) if (name == kinds[index]) return index + 1;
    invalid_binding("unknown planned storage kind");
}

}  // namespace

void materialize(llvm::Module &module, const std::string &path) {
    const auto bindings = read_bindings(path);
    const auto *header = module.getNamedMetadata("pyobf.archive.pending");
    const auto *records = module.getNamedMetadata("pyobf.archive.records");
    if (header == nullptr || header->getNumOperands() != 1 || header->getOperand(0)->getNumOperands() != 2 ||
        text_field(header->getOperand(0), 0) != "compiler-ir-v2" ||
        llvm::StringRef(text_field(header->getOperand(0), 1)).lower() != bindings.plan_hash ||
        records == nullptr || records->getNumOperands() != bindings.records.size() ||
        module.getNamedMetadata("pyobf.archive.prepared") != nullptr)
        invalid_binding("private bindings do not match an unfinished compiler plan");
    if (bindings.records.empty()) {
        materialize_empty_plan(module, bindings);
        return;
    }
    std::map<std::string, const RecordBinding *> by_id;
    std::map<llvm::Function *, WrapperView> replacements;
    std::map<llvm::Function *, std::pair<llvm::GlobalVariable *, const RecordBinding *>> owners;
    std::set<llvm::GlobalVariable *> caches, destinations;
    llvm::GlobalVariable *pool = nullptr;
    std::uint64_t body_offset = 40 + bindings.records.size() * 96;
    for (const auto &binding : bindings.records) {
        const auto *row = records->getOperand(binding.index);
        auto *destination = llvm::dyn_cast<llvm::GlobalVariable>(value_field(row, 1));
        auto *pending = llvm::dyn_cast<llvm::Function>(value_field(row, 2));
        if (row->getNumOperands() != 8 || text_field(row, 0) != binding.id ||
            number_field(row, 5) != binding.alignment || number_field(row, 7) != binding.size ||
            destination == nullptr || destination->isConstant() || !destination->hasLocalLinkage() ||
            destination->isThreadLocal() || destination->hasSection() || destination->hasComdat() ||
            destination->isExternallyInitialized() || destination->getAddressSpace() != 0 ||
            !destination->hasInitializer() || !destination->getInitializer()->isNullValue() ||
            destination->getAlign().value_or(module.getDataLayout().getABITypeAlign(destination->getValueType())).value() != binding.alignment ||
            module.getDataLayout().getTypeAllocSize(destination->getValueType()).getFixedValue() != binding.size ||
            !destinations.insert(destination).second || pending == nullptr || !pending->isDeclaration() ||
            !pending->hasFnAttribute("pyobf.archive.pending")) invalid_binding("planned record storage or pending gate differs");
        const auto view = verify_wrapper(module, binding, bindings);
        if (!caches.insert(view.cache).second || (pool != nullptr && pool != view.package) ||
            view.wrapper->getFunctionType() != pending->getFunctionType()) invalid_binding("record wrappers share cache or disagree on pool/ABI");
        if (pool == nullptr) { pool = view.package; verify_package(*pool, bindings); }
        const auto bytes = llvm::cast<llvm::ConstantDataSequential>(pool->getInitializer())->getRawDataValues();
        if (bytes.substr(0, 8) != "PYOBFAR1" || little(bytes, 8, 4) != 1 ||
            little(bytes, 12, 4) != bindings.records.size() || little(bytes, 32, 8) != bytes.size())
            invalid_binding("package header differs from planned records");
        const auto offset = 40 + binding.index * 96;
        if (little(bytes, offset, 4) != binding.index || little(bytes, offset + 4, 4) != kind_number(text_field(row, 3)) ||
            little(bytes, offset + 8, 4) != number_field(row, 4) || little(bytes, offset + 12, 4) != binding.alignment ||
            little(bytes, offset + 16, 8) != binding.size || little(bytes, offset + 24, 8) != body_offset ||
            little(bytes, offset + 32, 4) != number_field(row, 6) || little(bytes, offset + 36, 4) != 0 ||
            body_offset > bytes.size() || binding.size > bytes.size() - body_offset)
            invalid_binding("authenticated record descriptor differs from target storage");
        body_offset += binding.size;
        by_id.emplace(binding.id, &binding);
        replacements.emplace(pending, view);
        owners.emplace(pending, std::make_pair(destination, &binding));
    }
    const auto pool_bytes = llvm::cast<llvm::ConstantDataSequential>(pool->getInitializer())->getRawDataValues();
    if (body_offset != pool_bytes.size()) invalid_binding("package has unexplained trailing bytes");
    unsigned key_slots = 0, gates = 0;
    for (auto &function : module) for (auto &block : function) for (auto &instruction : block) {
        if (const auto *tag = instruction.getMetadata("pyobf.archive.key-slot")) {
            auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
            const auto found = by_id.find(text_field(tag, 0));
            const auto lane = number_field(tag, 2);
            if (store == nullptr || !store->isVolatile() || !store->getValueOperand()->getType()->isIntegerTy(32) ||
                !llvm::isa<llvm::ConstantInt>(store->getValueOperand()) ||
                !llvm::cast<llvm::ConstantInt>(store->getValueOperand())->isZero() ||
                found == by_id.end() || lane >= 8) invalid_binding("invalid unfinished key slot");
            std::uint32_t word = 0;
            for (unsigned byte = 0; byte < 4; ++byte) {
                const auto shift = module.getDataLayout().isLittleEndian() ? byte : 3 - byte;
                word |= std::uint32_t{found->second->key[lane * 4 + byte]} << (shift * 8);
            }
            store->setMetadata("pyobf.archive.key-material", llvm::MDNode::get(module.getContext(),
                llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt32Ty(module.getContext()), word))));
            ++key_slots;
        }
        if (auto *tag = instruction.getMetadata("pyobf.archive.gate")) {
            auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
            const auto found = call == nullptr ? replacements.end() : replacements.find(call->getCalledFunction());
            const auto owner = found == replacements.end() ? owners.end() : owners.find(found->first);
            const auto *capacity = call == nullptr || call->arg_size() != 3 ? nullptr :
                llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(2));
            if (found == replacements.end() || owner == owners.end() ||
                owner->second.second->id != text_field(tag, 0) || capacity == nullptr ||
                capacity->getZExtValue() != owner->second.second->size ||
                call->getArgOperand(1) != owner->second.first)
                invalid_binding("acquisition does not target its pending wrapper");
            call->setCalledFunction(found->second.wrapper);
            call->setMetadata("pyobf.archive.materialized", tag);
            ++gates;
        }
    }
    if (gates == 0 || key_slots != gates * 8) invalid_binding("key-slot and acquisition counts disagree");
    for (const auto &[pending, view] : replacements) {
        if (!pending->use_empty()) invalid_binding("pending gate has an unexplained use");
        view.wrapper->setLinkage(llvm::GlobalValue::InternalLinkage);
        view.wrapper->addFnAttr("pyobf.archive.wrapper", owners.at(pending).second->id);
        pending->eraseFromParent();
    }
    module.eraseNamedMetadata(module.getNamedMetadata("pyobf.archive.pending"));
    module.eraseNamedMetadata(module.getNamedMetadata("pyobf.archive.records"));
    module.getOrInsertNamedMetadata("pyobf.archive.prepared")->addOperand(llvm::MDNode::get(module.getContext(), {}));
}

}  // namespace pyobfuscator::native::archive
