#include "contribution_edge_source_fixture.hpp"
#include "contribution_frame_mutations.hpp"

#include <functional>
#include <iterator>

#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace pyobfuscator::native::cff;
using pyobfuscator::native::cff::test::EdgeSourceFixture;

int main() {
    if (!pyobfuscator::native::cff::test::check_framed_sources()) return 1;
    for (unsigned seed : {1, 2, 17, 41, 255}) {
        EdgeSourceFixture f(seed, true);
        if (llvm::verifyModule(f.module, &llvm::errs())) return 1;
        f.lower();
        const auto report = f.plan->report(false);
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.plan->verify_sources(*f.owner).empty() ||
                report.getInteger("original_edges") != 8 || report.getInteger("excluded_unwind_edges") != 1) return 1;
    }
    const std::pair<const char *, std::function<void(EdgeSourceFixture &)>> mutations[]{
        {"invoke bypasses EH bridge", [](EdgeSourceFixture &f) { f.invocation->setNormalDest(f.eh.invokes[0].normal); }},
        {"EH bridge bypasses contribution", [](EdgeSourceFixture &f) {
            llvm::cast<llvm::BranchInst>(f.eh.invokes[0].gateway->getTerminator())->setSuccessor(0, f.right);
        }},
        {"EH bridge uses another contribution", [](EdgeSourceFixture &f) {
            llvm::cast<llvm::BranchInst>(f.eh.invokes[0].gateway->getTerminator())->setSuccessor(0, f.gateway(0));
        }},
        {"unwind identity", [](EdgeSourceFixture &f) {
            auto *pad = llvm::BasicBlock::Create(f.context, "other.pad", f.owner);
            llvm::IRBuilder<> b(pad); auto *exception = b.CreateLandingPad(f.eh.pads[0].instruction->getType(), 0);
            exception->setCleanup(true); b.CreateResume(exception); f.invocation->setUnwindDest(pad);
        }},
        {"erased EH bridge", [](EdgeSourceFixture &f) {
            f.invocation->setNormalDest(f.eh.invokes[0].normal); f.eh.invokes[0].gateway->eraseFromParent();
        }},
        {"lowering replay", [](EdgeSourceFixture &f) { f.plan->invoke_lowered(*f.invocation, *f.eh.invokes[0].gateway); }},
    };
    for (const auto &[name, mutate] : mutations) {
        EdgeSourceFixture f(17, true); f.lower(); mutate(f);
        const auto reason = f.plan->verify_sources(*f.owner);
        if (llvm::verifyModule(f.module, &llvm::errs()) || reason.empty()) {
            llvm::errs() << "automatic invoke mutant escaped or is invalid: " << name << "; " << reason << "\n";
            return 1;
        }
    }
    llvm::outs() << "verified " << std::size(mutations) << " invoke source/lowering mutants and normal/unwind inventory\n";
}
