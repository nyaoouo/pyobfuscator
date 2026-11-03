#include "owner_reader_bindings.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

#include <map>
#include <set>

namespace pyobfuscator::native::cff {
namespace {
void require(bool condition, const char *message) { if (!condition) llvm::report_fatal_error(message); }
bool hex(llvm::StringRef value, unsigned size) {
    return value.size() == size && value.find_first_not_of("0123456789abcdef") == llvm::StringRef::npos;
}
const llvm::Function *function(const llvm::Constant *value) {
    return value == nullptr ? nullptr : llvm::dyn_cast<llvm::Function>(value->stripPointerCastsAndAliases());
}
bool integer(const llvm::Constant *value, unsigned width, std::uint64_t expected) {
    const auto *number = llvm::dyn_cast_or_null<llvm::ConstantInt>(value);
    return number && number->getBitWidth() == width && number->getZExtValue() == expected;
}
}
std::vector<OwnerReaderBinding> collect_owner_readers(const llvm::Module &module) {
    const auto *annotations = module.getNamedGlobal("llvm.global.annotations");
    if (annotations == nullptr || !annotations->hasInitializer()) return {};
    const auto *rows = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
    require(rows != nullptr, "owner readers need typed source annotations");
    std::map<std::pair<std::string, unsigned>, OwnerReaderBinding> bindings;
    std::set<const llvm::Function *> claimed;
    for (const auto &operand : rows->operands()) {
        const auto *row = llvm::dyn_cast<llvm::Constant>(operand);
        if (row == nullptr) continue;
        const auto *label = row->getAggregateElement(1u);
        const auto *global = label == nullptr ? nullptr : llvm::dyn_cast<llvm::GlobalVariable>(label->stripPointerCasts());
        const auto *data = global == nullptr || !global->hasInitializer() ? nullptr :
            llvm::dyn_cast<llvm::ConstantDataSequential>(global->getInitializer());
        if (data == nullptr || !data->isCString()) continue;
        auto text = data->getAsCString();
        bool capture = text.consume_front("pyobf.native.owner.capture.v1:");
        if (!capture && !text.consume_front("pyobf.native.owner.cache.v1:")) continue;
        llvm::SmallVector<llvm::StringRef, 4> fields; text.split(fields, ':');
        std::uint32_t index = 0, owner = 0; std::uint64_t key = 0;
        require(fields.size() == 4 && !fields[0].getAsInteger(10, index) && index < 64 &&
            !fields[1].getAsInteger(10, owner) && owner != 0 && hex(fields[2], 16) &&
            !fields[2].getAsInteger(16, key) && key != 0 && hex(fields[3], 64) &&
            fields[0] == std::to_string(index) && fields[1] == std::to_string(owner), "owner reader annotation is malformed");
        const auto *target = function(row->getAggregateElement(0u));
        require(target && !target->isDeclaration() && claimed.insert(target).second,
            "owner reader roles need distinct actual function definitions");
        auto &binding = bindings[{fields[3].str(), index}];
        require(binding.plan.empty() || (binding.owner == owner && binding.key == key), "owner reader role domains disagree");
        binding.index = index; binding.owner = owner; binding.key = key; binding.plan = fields[3].str();
        if (capture) binding.capture = target; else binding.cache = target;
    }
    if (bindings.empty()) return {};
    const auto &layout = module.getDataLayout();
    require(layout.isLittleEndian() && layout.getPointerSize() == 8, "owner reader binding ABI requires little-endian64 pointers");
    std::map<std::string, unsigned> counts;
    std::set<std::uint64_t> keys;
    std::vector<OwnerReaderBinding> result;
    for (auto &[id, binding] : bindings) {
        require(binding.capture && binding.cache && binding.index == counts[binding.plan]++ && keys.insert(binding.key).second,
            "owner readers lack complete unique contiguous role domains");
        binding.symbol = "pyobf_native_owner_bindings_" + binding.plan.substr(0, 24);
        binding.table = module.getNamedGlobal(binding.symbol);
        require(binding.table && binding.table->isConstant() && binding.table->hasInitializer() &&
            !binding.table->hasGlobalUnnamedAddr(), "owner reader binding storage must be distinct readonly data");
        const auto *array = llvm::dyn_cast<llvm::ConstantArray>(binding.table->getInitializer());
        const auto *entry = array == nullptr ? nullptr : llvm::dyn_cast_or_null<llvm::ConstantStruct>(array->getAggregateElement(binding.index));
        require(entry && entry->getNumOperands() == 5 && layout.getTypeAllocSize(entry->getType()) == 32 &&
            layout.getStructLayout(entry->getType())->getElementOffset(3) == 16 &&
            layout.getStructLayout(entry->getType())->getElementOffset(4) == 24 &&
            integer(entry->getAggregateElement(0u), 32, 1) && integer(entry->getAggregateElement(1u), 32, binding.owner) &&
            integer(entry->getAggregateElement(2u), 64, binding.key) &&
            function(entry->getAggregateElement(3u)) == binding.capture && function(entry->getAggregateElement(4u)) == binding.cache,
            "owner reader binding differs from its actual callback domain or code");
        result.push_back(binding);
    }
    for (const auto &binding : result) {
        const auto *array = llvm::cast<llvm::ConstantArray>(binding.table->getInitializer());
        require(array->getNumOperands() == counts.at(binding.plan), "owner reader binding count differs from its source roles");
    }
    return result;
}
}
