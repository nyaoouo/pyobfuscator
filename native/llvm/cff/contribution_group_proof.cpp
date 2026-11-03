#include "contribution_groups.hpp"
#include "contribution_mix.hpp"
#include "contribution_reference_origin.hpp"
#include "contribution_edges.hpp"
#include "contribution_query.hpp"
#include "scalar_proof.hpp"
#include "transition_proof.hpp"
#include "transition_layers.hpp"
#include "bogus_controls.hpp"

#include <map>
#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
std::string validate_contribution_group_gates(const llvm::Function &function, const TransitionLayers *layers, const BogusControls *controls) {
    if (controls != nullptr) if (const auto reason = controls->verify(function); !reason.empty()) return reason;
    const llvm::AllocaInst *root = nullptr;
    std::vector<const llvm::CallInst *> groups;
    unsigned calls = 0;
    for (const auto &body : function) for (const auto &instruction : body) {
        if (instruction.getMetadata("pyobf.contribution.root")) {
            if (root != nullptr || (root = llvm::dyn_cast<llvm::AllocaInst>(&instruction)) == nullptr ||
                    !valid_state_storage(root, &function.getEntryBlock())) return "contribution group state root is invalid";
        }
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        const auto *query = llvm::dyn_cast<llvm::CallInst>(&instruction);
        const auto *target = call == nullptr ? nullptr : call->getCalledFunction();
        const bool source = target != nullptr && reserved_contribution_query(target->getName());
        if (source) { if (query == nullptr) return "contribution source query is not an ordinary call"; ++calls; }
        if (instruction.getMetadata("pyobf.contribution.source") && !source) return "contribution source tag is not an actual query";
        if (instruction.getMetadata("pyobf.contribution.edge.anchor") &&
                (!source || !instruction.getMetadata("pyobf.contribution.query")))
            return "multiple Scope anchor tag is not a primary source query";
        if (instruction.getMetadata("pyobf.contribution.query")) {
            if (!source) return "contribution group primary is not an actual query";
            groups.push_back(query);
        }
    }
    unsigned expected_groups = 0, expected_calls = 0;
    if (root == nullptr || groups.empty() || !function.hasFnAttribute("pyobf.contribution.bound") ||
            function.getFnAttribute("pyobf.contribution.count").getValueAsString().getAsInteger(10, expected_groups) ||
            function.getFnAttribute("pyobf.contribution.queries").getValueAsString().getAsInteger(10, expected_calls) ||
            expected_groups != groups.size() || expected_calls != calls) return "contribution group inventory changed";
    const auto scope = function.getFnAttribute("pyobf.contribution.scope").getValueAsString();
    for (const auto *user : root->users()) {
        const auto *read = llvm::dyn_cast<llvm::LoadInst>(user);
        const auto *write = llvm::dyn_cast<llvm::StoreInst>(user);
        if (read != nullptr && layers != nullptr && layers->owns_state_read(*read)) continue;
        if (read != nullptr && controls != nullptr && controls->owns_state_read(*read)) continue;
        if (read != nullptr && read->getPointerOperand() == root && read->isSimple()) continue;
        if (write != nullptr && write->getPointerOperand() == root && write->isSimple()) continue;
        return "contribution group state storage escaped";
    }
    std::set<std::pair<std::uint32_t, std::uint32_t>> sites;
    std::set<const llvm::BasicBlock *> bodies;
    struct AnchorProof { const llvm::CallInst *query; std::uint32_t site, anchor, domain, source; };
    std::vector<AnchorProof> generated;
    std::map<std::uint32_t, std::vector<AnchorProof>> by_site;
    unsigned verified_calls = 0;
    for (const auto *primary : groups) {
        const auto *body = primary->getParent();
        const auto *node = primary->getMetadata("pyobf.contribution.query");
        if (node->getNumOperands() < 15) return "contribution group descriptor has invalid size";
        std::vector<std::uint32_t> fields;
        for (const auto &operand : node->operands()) {
            const auto *value = llvm::mdconst::dyn_extract<llvm::ConstantInt>(operand);
            if (value == nullptr || !value->getType()->isIntegerTy(32)) return "contribution group descriptor has invalid words";
            fields.push_back(value->getZExtValue());
        }
        const unsigned count = fields[12];
        const bool mixed = fields[0] == 3;
        const bool source_mixed = fields[0] == 4;
        const auto provider_tag = mixed && fields.size() == 14 + 2 * count ? fields.back() :
            scope == "v1" ? 2u : 1u;
        if ((fields[0] != 2 && !mixed && !source_mixed) ||
                (source_mixed ? scope != "source-mixed-v1" : mixed ? scope != "mixed-v1" : (!scope.empty() && scope != "v1")) ||
                (mixed && provider_tag != 1 && provider_tag != 2) ||
                fields[1] == 0 || fields[6] != 0 || fields[11] == 0 || count == 0 || count > 256 ||
                fields.size() != 13 + (source_mixed ? 3 : 2) * count + (mixed ? 1 : 0) ||
                fields[4] != fields[5] || fields[10] != fields[13] ||
                !sites.insert({fields[1], fields[2]}).second || !bodies.insert(body).second)
            return "contribution group identity changed";
        const auto queries = contribution_group_queries(*body);
        if (queries.size() != count || queries.front() != primary) return "contribution source query inventory changed";
        if (primary->arg_size() != (source_mixed ? 8u : 7u) || !primary->getType()->isIntegerTy(32))
            return "contribution group primary ABI changed";
        const auto *read = llvm::dyn_cast<llvm::LoadInst>(primary->getArgOperand(6));
        const auto *lease = primary->getArgOperand(0);
        const auto *branch = llvm::dyn_cast<llvm::BranchInst>(body->getTerminator());
        if (!lease->getType()->isPointerTy() || llvm::isa<llvm::ConstantPointerNull, llvm::UndefValue, llvm::PoisonValue>(lease) ||
                !simple_state_read(read, root, body) || branch == nullptr || !branch->isUnconditional())
            return "contribution group does not observe its live state or lease";
        const auto *edge_site = branch->getMetadata("pyobf.cff.site");
        const auto *edge_name = edge_site == nullptr || edge_site->getNumOperands() != 1 ? nullptr :
            llvm::dyn_cast<llvm::MDString>(edge_site->getOperand(0));
        const bool generated_edge = edge_name != nullptr && edge_name->getString().starts_with("contribution-edge.");
        const auto *anchor_tag = primary->getMetadata("pyobf.contribution.edge.anchor");
        const bool multiple_scopes = function.hasFnAttribute("pyobf.contribution.multiscope");
        if ((generated_edge && multiple_scopes) != (anchor_tag != nullptr) ||
                (!generated_edge && anchor_tag != nullptr))
            return "multiple Scope generated edge lost its anchor descriptor";
        if (anchor_tag != nullptr) {
            if (scope != "v1" || count != 1 || anchor_tag->getNumOperands() != 3)
                return "multiple Scope generated anchor descriptor is malformed";
            const auto *anchor_site = llvm::mdconst::dyn_extract<llvm::ConstantInt>(anchor_tag->getOperand(0));
            const auto *kind = llvm::mdconst::dyn_extract<llvm::ConstantInt>(anchor_tag->getOperand(1));
            const auto *origin = contribution_edge_reference_origin(
                const_cast<llvm::Value *>(primary->getArgOperand(0)), const_cast<llvm::Function &>(function));
            if (anchor_site == nullptr || !anchor_site->getType()->isIntegerTy(32) || anchor_site->isZero() ||
                    kind == nullptr || !kind->getType()->isIntegerTy(32) || origin == nullptr)
                return "multiple Scope generated anchor identity is invalid";
            if (kind->getZExtValue() == 1) {
                const auto *index = llvm::mdconst::dyn_extract<llvm::ConstantInt>(anchor_tag->getOperand(2));
                const auto *argument = llvm::dyn_cast<llvm::Argument>(origin);
                if (index == nullptr || !index->getType()->isIntegerTy(32) || argument == nullptr ||
                        argument->getArgNo() != index->getZExtValue())
                    return "multiple Scope generated query changed its anchored argument";
            } else if (kind->getZExtValue() == 2) {
                const auto *name = llvm::dyn_cast<llvm::MDString>(anchor_tag->getOperand(2));
                const auto *global = llvm::dyn_cast<llvm::GlobalVariable>(origin);
                if (name == nullptr || global == nullptr || global->getName() != name->getString())
                    return "multiple Scope generated query changed its anchored global";
            } else return "multiple Scope generated anchor kind is unsupported";
            generated.push_back({primary, fields[1], static_cast<std::uint32_t>(anchor_site->getZExtValue()),
                fields[11], fields[13]});
        }
        by_site[fields[1]].push_back({primary, fields[1], 0, fields[11], fields[13]});
        std::vector<std::pair<std::uint32_t, std::uint32_t>> labels;
        std::vector<const llvm::Value *> observed;
        std::set<std::uint32_t> unique;
        const llvm::Value *owned_ref = nullptr, *measured_ref = nullptr;
        for (unsigned index = 0; index != count; ++index) {
            const auto *query = queries[index]; const auto *target = query->getCalledFunction();
            if (query->arg_size() != (source_mixed ? 8u : 7u)) return "contribution source query ABI changed";
            const auto stride = source_mixed ? 3u : 2u;
            const auto label = fields[13 + stride * index], encoding = fields[14 + stride * index];
            const auto item_provider = source_mixed ? fields[15 + stride * index] : provider_tag;
            const auto expected_helper = contribution_group_query_name(
                item_provider == 2 ? "measured-scope-v1" : "owned-context-v1", fields[0]);
            const auto *tag = query->getMetadata("pyobf.contribution.source");
            const auto *ordinal = tag == nullptr || tag->getNumOperands() != (source_mixed ? 3u : 1u) ? nullptr :
                llvm::mdconst::dyn_extract<llvm::ConstantInt>(tag->getOperand(0));
            const auto *reference = source_mixed && tag != nullptr && tag->getNumOperands() == 3 ?
                llvm::mdconst::dyn_extract<llvm::ConstantInt>(tag->getOperand(1)) : nullptr;
            const auto *peer_reference = source_mixed && tag != nullptr && tag->getNumOperands() == 3 ?
                llvm::mdconst::dyn_extract<llvm::ConstantInt>(tag->getOperand(2)) : nullptr;
            const auto origin = source_mixed ? contribution_reference_argument(
                const_cast<llvm::Value *>(query->getArgOperand(0)), const_cast<llvm::Function &>(function)) : std::optional<unsigned>{};
            const auto peer_origin = source_mixed && query->arg_size() == 8 ? contribution_reference_argument(
                const_cast<llvm::Value *>(query->getArgOperand(7)), const_cast<llvm::Function &>(function)) : std::optional<unsigned>{};
            if (label == 0 || encoding != 1 || (item_provider != 1 && item_provider != 2) ||
                    !unique.insert(label).second ||
                    target->getName() != expected_helper ||
                    target->isVarArg() || target->getCallingConv() != llvm::CallingConv::C || query->getCallingConv() != llvm::CallingConv::C ||
                    query->arg_size() != (source_mixed ? 8u : 7u) || !query->getType()->isIntegerTy(32) || !query->doesNotThrow() || query->hasOperandBundles() ||
                    ordinal == nullptr || !scalar_constant(ordinal, index) ||
                    (source_mixed && (reference == nullptr || !reference->getType()->isIntegerTy(32) ||
                        peer_reference == nullptr || !peer_reference->getType()->isIntegerTy(32) ||
                        !origin || !peer_origin || reference->getZExtValue() != *origin ||
                        peer_reference->getZExtValue() != *peer_origin ||
                        *origin != (item_provider == 2 ? 1u : 0u) ||
                        *peer_origin != (item_provider == 2 ? 0u : 1u) ||
                        query->arg_size() != 8 || !query->getArgOperand(7)->getType()->isPointerTy() ||
                        llvm::isa<llvm::ConstantPointerNull, llvm::UndefValue, llvm::PoisonValue>(query->getArgOperand(7)))) ||
                    !read->comesBefore(query) ||
                    (!source_mixed && query->getArgOperand(0) != lease) || query->getArgOperand(6) != read)
                return "contribution source acquisition changed";
            if (source_mixed) {
                const auto *reference = query->getArgOperand(0);
                auto *&expected = item_provider == 2 ? measured_ref : owned_ref;
                if (llvm::isa<llvm::ConstantPointerNull, llvm::UndefValue, llvm::PoisonValue>(reference) ||
                        (expected != nullptr && expected != reference))
                    return "source-mixed contribution reference changed";
                expected = reference;
            }
            for (unsigned arg = 1; arg != 6; ++arg) {
                const auto expected = arg < 4 ? fields[6 + arg] : arg == 4 ? fields[1] : label;
                if (expected == 0 || !scalar_constant(query->getArgOperand(arg), expected)) return "contribution source public binding changed";
            }
            if (index != 0 && query->getMetadata("pyobf.contribution.query")) return "contribution source has another group primary";
            labels.push_back({label, encoding}); observed.push_back(query);
        }
        if (source_mixed && (owned_ref == nullptr || measured_ref == nullptr || owned_ref == measured_ref))
            return "source-mixed contribution references are absent or aliased";
        if (source_mixed) for (unsigned index = 0; index != count; ++index) {
            const auto provider = fields[15 + 3 * index];
            if (queries[index]->getArgOperand(7) != (provider == 2 ? owned_ref : measured_ref))
                return "source-mixed contribution peer reference changed";
        }
        const auto *store = llvm::dyn_cast_or_null<llvm::StoreInst>(branch->getPrevNode());
        const auto *salt_node = store == nullptr ? nullptr : store->getMetadata("pyobf.contribution.transition");
        const auto *salt = salt_node == nullptr || salt_node->getNumOperands() != 1 ? nullptr : llvm::mdconst::dyn_extract<llvm::ConstantInt>(salt_node->getOperand(0));
        if (salt == nullptr || !salt->getType()->isIntegerTy(32)) return "contribution group lost transition salt";
        const auto update = match_state_update(*body, root, salt->getZExtValue(), branch->getSuccessor(0));
        const auto *encoded = !update ? nullptr : layers == nullptr ? update->encoded : layers->normal_encoded(*body, update->encoded);
        if (layers != nullptr && !layers->at_state(*body, fields[2])) return "contribution group layer state differs from query state";
        const auto *combine = scalar_operation(encoded, llvm::Instruction::Xor, body);
        const auto *actual = combine == nullptr ? nullptr : contribution_mask_observation(combine->getOperand(0), fields[3], body);
        if (combine == nullptr || !scalar_constant(combine->getOperand(1), fields[4]) ||
                !match_contribution_mix(actual, plan_contribution_mix(fields[11], fields[9], fields[1], labels), observed, *body))
            return "contribution group does not consume every actual source in its framed state update";
        for (const auto &instruction : *body) {
            if (&instruction == read || instruction.comesBefore(read) || !instruction.comesBefore(store)) continue;
            if (const auto *write = llvm::dyn_cast<llvm::StoreInst>(&instruction); write != nullptr && write->getPointerOperand() == root)
                return "contribution group state changed during acquisition";
        }
        verified_calls += count;
    }
    if (verified_calls != calls) return "contribution group has untracked queries";
    for (const auto &edge : generated) {
        const auto found = by_site.find(edge.anchor);
        if (found == by_site.end() || found->second.size() != 1 ||
                found->second.front().query->getMetadata("pyobf.contribution.edge.anchor") != nullptr)
            return "multiple Scope generated edge has no unique explicit anchor query";
        const auto &anchor = found->second.front();
        if (edge.site == edge.anchor || edge.domain != anchor.domain || edge.source != anchor.source)
            return "multiple Scope generated policy differs from its explicit anchor";
        const auto *edge_origin = contribution_edge_reference_origin(
            const_cast<llvm::Value *>(edge.query->getArgOperand(0)), const_cast<llvm::Function &>(function));
        const auto *anchor_origin = contribution_edge_reference_origin(
            const_cast<llvm::Value *>(anchor.query->getArgOperand(0)), const_cast<llvm::Function &>(function));
        if (anchor_origin == nullptr) return "multiple Scope explicit anchor has no canonical origin";
        if (edge_origin == nullptr) return "multiple Scope generated query has no canonical origin";
        if (edge_origin != anchor_origin)
            return "multiple Scope generated pointer differs from its explicit anchor";
    }
    return {};
}
}
