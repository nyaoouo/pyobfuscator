#pragma once

#include "contribution_edge_flow_fixture.hpp"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {
inline bool check_parallel_contribution_flow() {
    for (unsigned seed : {1, 2, 17, 41}) for (bool folded : {false, true}) {
        EdgeFlowFixture f(seed, std::nullopt, true);
        auto *choice = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded));
        if (folded) choice->replaceAllUsesWith(choice->getTrueValue());
        if (llvm::verifyModule(f.module, &llvm::errs()) || !f.seal->verify(*f.owner).empty()) return false;
    }
    for (unsigned mutation = 0; mutation != 4; ++mutation) {
        EdgeFlowFixture f(17, std::nullopt, true);
        auto *choice = const_cast<llvm::SelectInst *>(llvm::cast<llvm::SelectInst>(f.update(f.start).encoded));
        if (mutation == 0) { llvm::IRBuilder<> b(choice); choice->setCondition(b.CreateNot(f.owner->getArg(0))); }
        const auto wrong = encode_delta(f.layout.states[f.start], f.layout.states[f.left], f.layout.transition_salt);
        if (mutation == 1) choice->setTrueValue(llvm::ConstantInt::get(choice->getType(), wrong));
        if (mutation == 2) choice->setFalseValue(llvm::ConstantInt::get(choice->getType(), wrong));
        if (mutation == 3) choice->replaceAllUsesWith(llvm::ConstantInt::get(choice->getType(), wrong));
        if (llvm::verifyModule(f.module, &llvm::errs()) || f.seal->verify(*f.owner).empty()) {
            llvm::errs() << "parallel contribution route mutant escaped: " << mutation << "\n"; return false;
        }
    }
    llvm::outs() << "8 parallel contribution routes and4 valid-IR condition/arm/constant mutants verified\n";
    return true;
}
}
