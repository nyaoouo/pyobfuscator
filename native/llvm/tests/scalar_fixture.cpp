#include "compare_codec.hpp"

#include <cstdint>
#include <string>
#include <vector>

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

namespace {

std::string hex(const llvm::APInt &value) {
    llvm::SmallString<40> result;
    value.toString(result, 16, false);
    return result.str().str();
}

llvm::json::Array pair(const llvm::APInt &value) {
    const auto wide = value.zextOrTrunc(128);
    return llvm::json::Array{hex(wide.trunc(64)), hex(wide.lshr(64).trunc(64))};
}

void store_pair(llvm::IRBuilder<> &builder, llvm::Value *value, llvm::Value *output) {
    auto *wide = builder.CreateZExtOrTrunc(value, builder.getInt128Ty());
    builder.CreateStore(builder.CreateTrunc(wide, builder.getInt64Ty()), output);
    auto *high = builder.CreateTrunc(builder.CreateLShr(wide, 64), builder.getInt64Ty());
    builder.CreateStore(high, builder.CreateGEP(builder.getInt8Ty(), output, builder.getInt64(8)));
    builder.CreateRetVoid();
}

}  // namespace

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    using namespace pyobfuscator::native::cff;
    llvm::LLVMContext context;
    llvm::Module module("native-scalar-contract", context);
    auto *i32 = llvm::Type::getInt32Ty(context);
    auto *i64 = llvm::Type::getInt64Ty(context);
    auto *pointer = llvm::PointerType::getUnqual(context);
    auto *mask_type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), {i32, pointer}, false);
    auto *compare_type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), {i32, i64, i64, pointer}, false);
    const std::uint32_t salt = 0xc137a95du;
    llvm::json::Array records;
    std::uint32_t random = 0x12345678u;
    for (unsigned width = 1; width <= 128; ++width) {
        auto *type = llvm::IntegerType::get(context, width);
        for (const auto domain : {ScalarMaskDomain::literal, ScalarMaskDomain::comparison,
                                 ScalarMaskDomain::archive, ScalarMaskDomain::reference, ScalarMaskDomain::preparation,
                                 ScalarMaskDomain::local, ScalarMaskDomain::import_route}) {
            const auto label = domain == ScalarMaskDomain::literal ? "mask_lit_" :
                domain == ScalarMaskDomain::comparison ? "mask_cmp_" :
                domain == ScalarMaskDomain::archive ? "mask_arc_" :
                domain == ScalarMaskDomain::reference ? "mask_ref_" : domain == ScalarMaskDomain::preparation ? "mask_prep_" :
                domain == ScalarMaskDomain::local ? "mask_local_" : "mask_import_";
            auto *function = llvm::Function::Create(mask_type, llvm::Function::ExternalLinkage,
                                                     label + std::to_string(width), module);
            auto *entry = llvm::BasicBlock::Create(context, "entry", function);
            llvm::IRBuilder<> builder(entry);
            store_pair(builder, emit_scalar_mask(builder, type, function->getArg(0), salt, domain),
                         function->getArg(1));
        }
        if (width >= 2) {
            auto *function = llvm::Function::Create(compare_type, llvm::Function::ExternalLinkage,
                                                     "encode_" + std::to_string(width), module);
            auto *entry = llvm::BasicBlock::Create(context, "entry", function);
            llvm::IRBuilder<> builder(entry);
            auto *low = builder.CreateZExt(function->getArg(1), builder.getInt128Ty());
            auto *high = builder.CreateShl(builder.CreateZExt(function->getArg(2), builder.getInt128Ty()), 64);
            auto *input = builder.CreateZExtOrTrunc(builder.CreateOr(low, high), type);
            auto *key = emit_scalar_mask(builder, type, function->getArg(0), salt, ScalarMaskDomain::comparison);
            store_pair(builder, emit_comparison(builder, input, key, make_compare_codec(width, salt)),
                         function->getArg(3));
        }
        std::vector<llvm::APInt> values;
        if (width <= 8) {
            for (unsigned value = 0; value < (1u << width); ++value) values.emplace_back(width, value);
        } else {
            values = {llvm::APInt(width, 0), llvm::APInt(width, 1), llvm::APInt::getAllOnes(width),
                      llvm::APInt::getSignMask(width), llvm::APInt::getSignedMaxValue(width)};
            for (unsigned index = 0; index < 64; ++index) {
                llvm::APInt value(128, 0);
                for (unsigned offset = 0; offset < 128; offset += 32) {
                    random = random * 1664525u + 1013904223u;
                    value |= llvm::APInt(128, random).shl(offset);
                }
                values.push_back(value.trunc(width));
            }
        }
        for (const auto &value : values) {
            const auto state = width <= 8 ? 0xffffffffu : (random = random * 1664525u + 1013904223u);
            const auto key = scalar_mask_value(width, state, salt, ScalarMaskDomain::comparison);
            records.push_back(llvm::json::Object{
                {"width", width}, {"state", state}, {"input", pair(value)},
                {"literal", pair(scalar_mask_value(width, state, salt))}, {"key", pair(key)},
                {"archive", pair(scalar_mask_value(width, state, salt, ScalarMaskDomain::archive))},
                {"reference", pair(scalar_mask_value(width, state, salt, ScalarMaskDomain::reference))},
                {"preparation", pair(scalar_mask_value(width, state, salt, ScalarMaskDomain::preparation))},
                {"locals", pair(scalar_mask_value(width, state, salt, ScalarMaskDomain::local))},
                {"imports", pair(scalar_mask_value(width, state, salt, ScalarMaskDomain::import_route))},
                {"encoded", pair(width >= 2 ? encode_comparison(value, key, make_compare_codec(width, salt)) : value)}});
        }
    }
    std::error_code error;
    llvm::raw_fd_ostream ir(argv[1], error, llvm::sys::fs::OF_Text);
    if (error) return 2;
    module.print(ir, nullptr);
    ir.flush();
    if (ir.has_error()) return 3;
    llvm::raw_fd_ostream output(argv[2], error, llvm::sys::fs::OF_Text);
    if (error) return 4;
    output << llvm::json::Value(std::move(records)) << '\n';
    output.flush();
    return output.has_error() ? 5 : 0;
}
