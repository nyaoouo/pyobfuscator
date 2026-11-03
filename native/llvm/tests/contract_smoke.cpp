#include "mutation_guard.hpp"
#include "site_alias_graph.hpp"
#include "site_report.hpp"
#include "cfg_origin.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"

using pyobfuscator::native::cff::CfgSeal;
using pyobfuscator::native::cff::SiteRecord;
using pyobfuscator::native::cff::validate_site_alias;

int main() {
    llvm::LLVMContext context;
    llvm::Module module("mutation-contract", context);
    auto *type = llvm::FunctionType::get(llvm::Type::getInt32Ty(context), false);
    auto *function = llvm::Function::Create(type, llvm::Function::ExternalLinkage,
                                           "selected", module);
    auto *entry = llvm::BasicBlock::Create(context, "entry", function);
    auto *yes = llvm::BasicBlock::Create(context, "yes", function);
    auto *no = llvm::BasicBlock::Create(context, "no", function);
    llvm::IRBuilder<> builder(entry);
    auto *branch = builder.CreateCondBr(builder.getTrue(), yes, no);
    llvm::IRBuilder<>(yes).CreateRet(builder.getInt32(1));
    llvm::IRBuilder<>(no).CreateRet(builder.getInt32(2));
    const CfgSeal seal(*function);
    if (!seal.check(*function).empty()) return 1;
    builder.SetInsertPoint(branch);
    auto *slot = builder.CreateAlloca(builder.getInt32Ty());
    builder.CreateStore(builder.getInt32(3), slot);
    if (!seal.check(*function).empty()) return 2;
    branch->setSuccessor(0, no);
    if (seal.check(*function).empty()) return 3;
    branch->setSuccessor(0, yes);
    if (!seal.check(*function).empty()) return 4;
    auto *extra = llvm::BasicBlock::Create(context, "late-structural-mutation", function);
    llvm::IRBuilder<>(extra).CreateRet(builder.getInt32(9));
    if (seal.check(*function).empty()) return 5;
    extra->eraseFromParent();
    if (!seal.check(*function).empty()) return 6;
    auto *helper = llvm::Function::Create(type, llvm::Function::InternalLinkage,
                                         "late-helper", module);
    auto *helper_entry = llvm::BasicBlock::Create(context, "entry", helper);
    llvm::IRBuilder<>(helper_entry).CreateRet(builder.getInt32(1));
    if (seal.check(*function).empty()) return 7;
    std::vector<SiteRecord> sites(3);
    std::map<std::string, unsigned> positions;
    for (unsigned index = 0; index < sites.size(); ++index) {
        auto &site = sites[index];
        site.id = std::to_string(index);
        site.component = "integer-literals";
        site.status = "eligible";
        positions[site.id] = index;
    }
    sites[0].status = "relocated";
    sites[0].replacement = "1";
    if (validate_site_alias(sites, positions, sites[0]).empty()) return 8;
    sites[1].status = "applied";
    sites[1].applied_instances = 1;
    if (!validate_site_alias(sites, positions, sites[0]).empty()) return 9;
    sites[1].status = "coalesced";
    sites[1].replacement = "2";
    sites[2].status = "applied";
    sites[2].applied_instances = 1;
    if (!validate_site_alias(sites, positions, sites[0]).empty()) return 10;
    sites[2].component = "cfg";
    if (validate_site_alias(sites, positions, sites[0]).empty()) return 11;
    sites[2].component = "integer-literals";
    sites[1].replacement = "0";
    if (validate_site_alias(sites, positions, sites[0]).empty()) return 12;
    sites[1].replacement = "missing";
    if (validate_site_alias(sites, positions, sites[0]).empty()) return 13;
    sites[1].replacement = "2";
    sites[2].instances = 2;
    if (validate_site_alias(sites, positions, sites[0]).empty()) return 14;
    pyobfuscator::native::cff::CfgOrigins origins;
    std::vector<const llvm::BasicBlock *> before;
    for (const auto &block : *function) {
        before.push_back(&block);
        origins.set(block, pyobfuscator::native::cff::BlockRole::real);
    }
    const CfgSeal phase_seal(*function);
    auto *decoy = llvm::BasicBlock::Create(context, "unclassified-prepare", function);
    llvm::IRBuilder<>(decoy).CreateRet(builder.getInt32(7));
    if (origins.validate_new_blocks(*function, before).empty()) return 15;
    origins.set(*decoy, pyobfuscator::native::cff::BlockRole::decoy);
    if (!origins.validate_new_blocks(*function, before).empty()) return 16;
    if (!phase_seal.check_definitions(*function).empty() || phase_seal.check(*function).empty()) return 17;
    return 0;
}
