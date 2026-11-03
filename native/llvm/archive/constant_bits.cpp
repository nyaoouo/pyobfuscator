#include "plan.hpp"

#include "llvm/ADT/APInt.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"

namespace pyobfuscator::native::archive {
namespace {

constexpr std::uint64_t max_record_bytes = 16 * 1024 * 1024;

std::string append_bits(llvm::Constant &value, const llvm::DataLayout &layout,
                          std::vector<std::uint8_t> &output, unsigned depth) {
    if (depth > 32) return "archive constant nesting exceeds 32 levels";
    if (llvm::isa<llvm::UndefValue>(value) || llvm::isa<llvm::PoisonValue>(value))
        return "archive storage cannot contain undef or poison";
    const auto size = layout.getTypeAllocSize(value.getType());
    if (size.isScalable() || size.getFixedValue() > max_record_bytes - output.size())
        return "archive storage exceeds the fixed record byte budget";
    if (auto *array = llvm::dyn_cast<llvm::ArrayType>(value.getType())) {
        if (array->getNumElements() != 0 && layout.getTypeAllocSize(array->getElementType()).isZero())
            return "archive arrays with zero-sized elements are unsupported";
        for (std::uint64_t index = 0; index < array->getNumElements(); ++index) {
            auto *element = value.getAggregateElement(static_cast<unsigned>(index));
            if (element == nullptr) return "archive array element is not a concrete constant";
            if (const auto reason = append_bits(*element, layout, output, depth + 1); !reason.empty())
                return reason;
        }
        return {};
    }
    llvm::APInt bits(1, 0);
    if (const auto *integer = llvm::dyn_cast<llvm::ConstantInt>(&value)) {
        if (integer->getBitWidth() > 128) return "archive integers support i1 through i128";
        bits = integer->getValue();
    } else if (const auto *floating = llvm::dyn_cast<llvm::ConstantFP>(&value)) {
        if (value.getType()->isPPC_FP128Ty()) return "archive double-double storage is unsupported";
        bits = floating->getValueAPF().bitcastToAPInt();
        if (bits.getBitWidth() != 16 && bits.getBitWidth() != 32 && bits.getBitWidth() != 64 &&
            bits.getBitWidth() != 80 && bits.getBitWidth() != 128)
            return "archive floating representation is unsupported";
    } else {
        return "archive storage supports scalar integers/floats and fixed arrays only";
    }
    const auto width = static_cast<unsigned>(layout.getTypeStoreSize(value.getType()).getFixedValue());
    if (size.getFixedValue() > 16 || (llvm::isa<llvm::ConstantFP>(value) &&
        bits.getBitWidth() != 80 && size.getFixedValue() != width))
        return "archive scalar storage layout is unsupported";
    bits = bits.zextOrTrunc(width * 8);
    for (unsigned index = 0; index < width; ++index) {
        const auto byte = layout.isLittleEndian() ? index : width - index - 1;
        output.push_back(static_cast<std::uint8_t>(bits.extractBitsAsZExtValue(8, byte * 8)));
    }
    output.resize(output.size() + size.getFixedValue() - width, 0);
    return {};
}

}  // namespace

std::string encode_storage(llvm::Constant &constant, const llvm::DataLayout &layout,
                             PlannedRecord &record) {
    if (!constant.getType()->isSized()) return "archive storage requires a sized type";
    if (const auto reason = append_bits(constant, layout, record.bytes, 0); !reason.empty()) return reason;
    record.initializer = &constant;
    record.alignment = static_cast<unsigned>(layout.getABITypeAlign(constant.getType()).value());
    record.byte_order = layout.isLittleEndian() ? 1 : 2;
    record.bit_width = constant.getType()->getScalarSizeInBits();
    switch (constant.getType()->getTypeID()) {
    case llvm::Type::IntegerTyID: record.kind = "integer"; break;
    case llvm::Type::HalfTyID: record.kind = "binary16"; break;
    case llvm::Type::BFloatTyID: record.kind = "bfloat16"; break;
    case llvm::Type::FloatTyID: record.kind = "binary32"; break;
    case llvm::Type::DoubleTyID: record.kind = "binary64"; break;
    case llvm::Type::X86_FP80TyID: record.kind = "x87_80"; break;
    case llvm::Type::FP128TyID: record.kind = "binary128"; break;
    default:
        record.kind = "bytes";
        record.bit_width = 8;
        record.byte_order = 0;
        if (const auto *array = llvm::dyn_cast<llvm::ArrayType>(constant.getType())) {
            auto *element = llvm::dyn_cast<llvm::IntegerType>(array->getElementType());
            const auto width = element == nullptr ? 0 : element->getBitWidth();
            if ((width == 8 || width == 16 || width == 32) && record.bytes.size() >= width / 8 &&
                layout.getTypeAllocSize(element).getFixedValue() == width / 8) {
                bool zero = true;
                for (unsigned index = 0; index < width / 8; ++index)
                    zero &= record.bytes[record.bytes.size() - 1 - index] == 0;
                if (zero) {
                    record.kind = "code_units" + std::to_string(width);
                    record.bit_width = width;
                    record.byte_order = width == 8 ? 0 : (layout.isLittleEndian() ? 1 : 2);
                }
            }
        }
    }
    if (record.alignment > 4096) return "archive storage alignment exceeds 4096";
    return {};
}

}  // namespace pyobfuscator::native::archive
