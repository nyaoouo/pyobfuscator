#pragma once

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

namespace pyobfuscator::native::cff::test {
// Exercise the shared flow boundary; actual table/frame graphs have separate
// production contracts and executable component-composition fixtures.
template<class Fixture, class Verify>
bool check_state_binding_mutations(const char *profile, Verify verify) {
    struct Tag { const char *name; unsigned state; bool read; };
    const Tag tags[]{
        {"pyobf.ref.state", 0, true}, {"pyobf.ref.bound", 4, false},
        {"pyobf.prep.state", 0, true}, {"pyobf.prep.bound", 3, false},
        {"pyobf.prep.step-bound", 2, false},
        {"pyobf.local.state", 0, true}, {"pyobf.local.bound", 3, false}};
    unsigned positives = 0, refused = 0;
    for (const auto &tag : tags) for (unsigned mode = 0; mode != (tag.read ? 8u : 5u); ++mode) {
        Fixture f;
        llvm::IRBuilder<> builder(const_cast<llvm::StoreInst *>(f.update(f.start).store));
        auto *read = builder.CreateLoad(builder.getInt32Ty(), f.state);
        llvm::SmallVector<llvm::Metadata *, 5> fields(tag.state + 1,
            llvm::ConstantAsMetadata::get(builder.getInt32(0)));
        fields[tag.state] = llvm::ConstantAsMetadata::get(builder.getInt32(f.layout.states[f.start]));
        if (mode == 1) fields[tag.state] = llvm::ConstantAsMetadata::get(builder.getInt32(f.layout.states[f.start] ^ 1));
        if (mode == 2) fields.clear();
        if (mode == 3) fields[tag.state] = llvm::ConstantAsMetadata::get(builder.getInt64(f.layout.states[f.start]));
        read->setMetadata(tag.name, llvm::MDNode::get(f.context, fields));
        if (mode == 4) read->moveBefore(f.returned->getTerminator());
        if (mode == 5) {
            llvm::IRBuilder<> entry(&*f.entry->getFirstInsertionPt());
            auto *other = entry.CreateAlloca(entry.getInt32Ty()); entry.CreateStore(entry.getInt32(0), other);
            read->setOperand(0, other);
        }
        if (mode == 6) read->setVolatile(true);
        if (mode == 7) read->setAtomic(llvm::AtomicOrdering::Unordered);
        const auto error = verify(f);
        if (llvm::verifyModule(f.module, &llvm::errs()) || (error.empty() != (mode == 0))) {
            llvm::errs() << profile << " state/root binding contract differs: " << tag.name << "/" << mode << "; " << error << "\n";
            return false;
        }
        mode == 0 ? ++positives : ++refused;
    }
    llvm::outs() << profile << " verified " << positives << " state/root binding positives and " << refused << " mutants\n";
    return true;
}
}
