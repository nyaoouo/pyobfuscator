#include "frame_fixture.hpp"
#include "call_preparation.hpp"

#include <functional>

#include "llvm/Transforms/Utils/Local.h"

namespace {
using namespace pyobfuscator::native::cff;

struct Fixture : test::Fixture {
    std::vector<llvm::GetElementPtrInst *> addresses;
    std::vector<llvm::Instruction *> steps;

    explicit Fixture(std::uint32_t salt = 0x12345678u) : test::Fixture(true) {
        module.getOrInsertNamedMetadata("pyobf.prep.inventory")->addOperand(
            module.getNamedMetadata("pyobf.frame.inventory")->getOperand(0));
        for (auto *function : {owner, helper}) {
            const bool invoker = function == helper;
            std::map<llvm::Instruction *, std::string> events;
            for (auto &block : *function) for (auto &instruction : block) {
                if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction)) {
                    llvm::IRBuilder<> builder(context);
                    gep->setMetadata("pyobf.prep.pending", llvm::MDNode::get(context, {
                        descriptor, llvm::ConstantAsMetadata::get(llvm::cast<llvm::ConstantInt>(gep->getOperand(2))),
                        llvm::ConstantAsMetadata::get(builder.getInt32(salt))}));
                }
                if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&instruction))
                    events[load] = invoker ? (load == target_load ? "read-target" : "read-argument") : "pyobf.frame.result";
                if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction))
                    events[store] = invoker ? "pyobf.frame.return-store" :
                        store == target_store ? "pyobf.frame.target" : "write-argument";
            }
            events[invoker ? inner : outer] = invoker ? "invoke-invoker" : "invoke-caller";
            (invoker ? inner : outer)->setMetadata("pyobf.prep.anchor", llvm::MDNode::get(context, {
                descriptor, llvm::MDString::get(context, invoker ? "invoker" : "caller")}));
            for (auto &instruction : function->getEntryBlock()) if (!llvm::isa<llvm::AllocaInst>(instruction)) {
                function->getEntryBlock().splitBasicBlock(&instruction, "start"); break;
            }
            std::vector<llvm::Instruction *> ordered;
            for (auto &block : *function) for (auto &instruction : block) if (events.count(&instruction)) ordered.push_back(&instruction);
            for (auto *event : ordered) {
                auto *step = event->getParent()->splitBasicBlock(event, "step");
                step->splitBasicBlock(event->getNextNode(), "continue");
            }
            auto &entry = function->getEntryBlock();
            llvm::IRBuilder<> builder(&*entry.getFirstInsertionPt());
            auto *slot = builder.CreateAlloca(builder.getInt32Ty());
            std::vector<llvm::Instruction *> demote;
            for (auto &block : *function) for (auto &instruction : block) {
                if (llvm::isa<llvm::AllocaInst>(instruction) && &block == &entry) continue;
                for (const auto *user : instruction.users()) if (const auto *use = llvm::dyn_cast<llvm::Instruction>(user);
                    use != nullptr && use->getParent() != &block) { demote.push_back(&instruction); break; }
            }
            for (auto *instruction : demote) llvm::DemoteRegToStack(*instruction, false, entry.getFirstInsertionPt());
            std::vector<llvm::BasicBlock *> bodies;
            std::map<const llvm::BasicBlock *, unsigned> states;
            for (auto &block : *function) if (&block != &entry) {
                bodies.push_back(&block); states[&block] = bodies.size() * 100;
            }
            for (auto *body : bodies) for (auto iterator = body->begin(); iterator != body->end();) {
                auto &instruction = *iterator++;
                if (instruction.getMetadata("pyobf.prep.pending")) {
                    auto *old = llvm::cast<llvm::GetElementPtrInst>(&instruction);
                    auto *bound = emit_prepared_address(*old, slot, states[body]);
                    old->replaceAllUsesWith(bound); old->eraseFromParent(); addresses.push_back(bound); continue;
                }
                if (events.count(&instruction)) {
                    instruction.setMetadata("pyobf.prep.step-bound", llvm::MDNode::get(context, {
                        descriptor, llvm::MDString::get(context, events.at(&instruction)),
                        llvm::ConstantAsMetadata::get(builder.getInt32(states[body]))}));
                    steps.push_back(&instruction);
                }
            }
            auto *dispatch = llvm::BasicBlock::Create(context, "dispatch", function);
            builder.SetInsertPoint(dispatch);
            auto *state = builder.CreateLoad(builder.getInt32Ty(), slot);
            std::function<llvm::BasicBlock *(unsigned)> tree = [&](unsigned index) {
                auto *leaf = llvm::BasicBlock::Create(context, "leaf", function);
                llvm::IRBuilder<> leaf_builder(leaf); leaf_builder.CreateBr(bodies[index]);
                if (index + 1 == bodies.size()) return leaf;
                auto *node = llvm::BasicBlock::Create(context, "compare", function);
                llvm::IRBuilder<> node_builder(node);
                node_builder.CreateCondBr(node_builder.CreateICmpUGE(state, node_builder.getInt32(states[bodies[index + 1]])),
                    tree(index + 1), leaf);
                return node;
            };
            builder.CreateBr(tree(0));
            entry.getTerminator()->eraseFromParent(); builder.SetInsertPoint(&entry);
            builder.CreateStore(builder.getInt32(states[bodies.front()]), slot); builder.CreateBr(dispatch);
            for (auto *body : bodies) if (auto *edge = llvm::dyn_cast<llvm::BranchInst>(body->getTerminator())) {
                const auto next = states.at(edge->getSuccessor(0)); edge->eraseFromParent(); builder.SetInsertPoint(body);
                builder.CreateStore(builder.getInt32(next), slot); builder.CreateBr(dispatch);
            }
        }
    }
};

bool valid(const Fixture &fixture) {
    return verify_call_frames(fixture.module).empty() && verify_call_preparation(fixture.module).empty();
}
}  // namespace

int main() {
    Fixture baseline;
    if (llvm::verifyModule(baseline.module) || !valid(baseline)) {
        llvm::errs() << verify_call_frames(baseline.module) << '\n' << verify_call_preparation(baseline.module) << '\n';
        return 1;
    }
    for (const auto salt : {0x9e3779b9u, 0x9e3779b9u ^ 100u}) {
        Fixture zero_constant(salt);
        if (llvm::verifyModule(zero_constant.module) || !valid(zero_constant)) return 2;
    }
    const std::function<void(Fixture &)> mutations[]{
        [](Fixture &f) { f.addresses[0]->setOperand(1, llvm::ConstantInt::get(llvm::Type::getInt32Ty(f.context), 0)); },
        [](Fixture &f) { f.addresses[0]->setMetadata("pyobf.prep.bound", nullptr); },
        [](Fixture &f) { f.steps[0]->setMetadata("pyobf.prep.step-bound", nullptr); },
        [](Fixture &f) {
            auto *tag = f.steps[0]->getMetadata("pyobf.prep.step-bound"); llvm::IRBuilder<> b(f.context);
            f.steps[0]->setMetadata("pyobf.prep.step-bound", llvm::MDNode::get(f.context,
                {tag->getOperand(0).get(), tag->getOperand(1).get(), llvm::ConstantAsMetadata::get(b.getInt32(0xffffffffu))}));
        },
        [](Fixture &f) { f.module.eraseNamedMetadata(f.module.getNamedMetadata("pyobf.prep.inventory")); },
        [](Fixture &f) { auto *inventory = f.module.getNamedMetadata("pyobf.prep.inventory"); inventory->addOperand(inventory->getOperand(0)); },
        [](Fixture &f) { f.addresses[0]->setIsInBounds(true); },
        [](Fixture &f) { f.addresses[0]->setOperand(0, f.owner->getArg(0)); },
        [](Fixture &f) {
            for (auto &block : *f.owner) for (auto &i : block) if (i.getName().starts_with("pyobf.preparation.decode")) {
                i.setOperand(1, llvm::ConstantInt::get(i.getType(), 0)); return;
            }
        },
        [](Fixture &f) {
            for (auto &block : *f.owner) for (auto &i : block) if (i.getName().starts_with("pyobf.preparation.index")) {
                i.setOperand(1, llvm::ConstantInt::get(i.getType(), 1)); return;
            }
        },
        [](Fixture &f) {
            for (auto &block : *f.owner) for (auto &i : block) if (i.getMetadata("pyobf.cff.public-coefficient")) {
                i.setOperand(1, llvm::ConstantInt::get(i.getType(), 3)); return;
            }
        },
        [](Fixture &f) {
            auto *address = f.addresses[0]; llvm::IRBuilder<> b(address);
            address->setOperand(1, b.CreateXor(address->getOperand(1), b.CreateXor(address->getOperand(1), b.getInt32(0))));
        },
        [](Fixture &f) {
            for (auto &block : *f.owner) for (auto &i : block) if (i.getMetadata("pyobf.prep.state")) {
                llvm::IRBuilder<> b(&*f.owner->getEntryBlock().getFirstInsertionPt()); auto *other = b.CreateAlloca(b.getInt32Ty());
                i.setOperand(0, other); return;
            }
        },
        [](Fixture &f) {
            llvm::AllocaInst *slot = nullptr;
            for (auto &i : f.owner->getEntryBlock()) if (i.getMetadata("pyobf.prep.state-slot")) slot = llvm::cast<llvm::AllocaInst>(&i);
            llvm::IRBuilder<> b(f.outer); auto *escape = new llvm::GlobalVariable(f.module, b.getPtrTy(), false,
                llvm::GlobalValue::PrivateLinkage, llvm::ConstantPointerNull::get(b.getPtrTy()));
            b.CreateStore(slot, escape);
        },
        [](Fixture &f) {
            auto *load = llvm::cast<llvm::LoadInst>(f.inner->getCalledOperand());
            auto *slot = llvm::cast<llvm::AllocaInst>(load->getPointerOperand()); llvm::IRBuilder<> b(f.inner);
            b.CreateStore(f.target, slot);
        },
        [](Fixture &f) { f.outer->setMetadata("pyobf.prep.anchor", nullptr); },
        [](Fixture &f) { f.addresses[0]->setMetadata("pyobf.prep.pending", llvm::MDNode::get(f.context, {})); }
    };
    for (unsigned index = 0; index < std::size(mutations); ++index) {
        Fixture fixture; mutations[index](fixture);
        if (valid(fixture)) { llvm::errs() << "preparation mutation unexpectedly accepted: " << index << '\n'; return 10 + index; }
    }
    finish_call_frames(baseline.module); strip_call_preparation(baseline.module);
    return llvm::verifyModule(baseline.module) || !verify_call_preparation(baseline.module).empty() ? 40 : 0;
}
