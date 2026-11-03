#include "call_frames.hpp"
#include "call_preparation.hpp"
#include "frame_profile.hpp"
#include "cff.hpp"
#include "site_provenance.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

void plan_frame_component(llvm::Module &module, const std::map<std::string, ResolvedRecipe> &recipes,
                            std::vector<GeneratedDefinition> &generated, llvm::StringRef component) {
    for (const auto &[name, recipe] : recipes) {
        auto *owner = module.getFunction(name);
        if (!recipe.enabled(component) || owner == nullptr || !validate_configured(*owner, recipe).empty()) continue;
        std::set<llvm::Instruction *> prepared;
        if (recipe.enabled("call-preparation"))
            for (const auto &site : discover_call_preparation(*owner, recipe))
                if (site.reason.empty()) prepared.insert(site.instruction);
        unsigned sequence = 0;
        for (const auto &site : find_component(component)->discover(*owner, recipe)) {
            if (!site.reason.empty()) continue;
            auto &call = *llvm::cast<llvm::CallBase>(site.instruction);
            const auto identity = instruction_site_id(call, component, 0);
            const auto route = component_seed(recipe.seeds.at(component.str()), name, identity);
            const auto helper_name = std::string(component == "external-calls" ? "__pyobf_external_" : "__pyobf_frame_") +
                std::to_string(route) + "_" + std::to_string(sequence++);
            if (module.getNamedValue(helper_name) != nullptr)
                llvm::report_fatal_error("native call frame helper name collides with an existing symbol");
            auto &context = module.getContext();
            auto *helper_type = llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                {llvm::PointerType::getUnqual(context)}, false);
            auto *helper = llvm::Function::Create(helper_type, llvm::Function::InternalLinkage, helper_name, module);
            helper->addFnAttr(llvm::Attribute::NoInline);
            if (call.doesNotThrow()) helper->addFnAttr(llvm::Attribute::NoUnwind);
            if (owner->hasUWTable()) helper->setUWTableKind(owner->getUWTableKind());
            auto *target = call.getCalledFunction();
            const auto layout = call_frame_layout(call, recipe);
            auto *descriptor = frame_metadata(helper, target, layout);
            helper->setMetadata("pyobf.frame.helper", descriptor);
            std::vector<llvm::Metadata *> abi{llvm::ConstantAsMetadata::get(
                llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), call.getCallingConv()))};
            for (const auto index : {llvm::AttributeList::FunctionIndex, llvm::AttributeList::ReturnIndex})
                abi.push_back(llvm::MDString::get(context, call.getAttributes().getAsString(index)));
            for (unsigned index = 0; index < call.arg_size(); ++index)
                abi.push_back(llvm::MDString::get(context, call.getAttributes().getAsString(index + 1)));
            helper->setMetadata("pyobf.frame.abi", llvm::MDNode::get(context, abi));
            llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", helper));
            const auto read = [&](unsigned field) {
                auto *address = builder.CreateStructGEP(layout.type, helper->getArg(0), field, "pyobf.frame.field");
                return builder.CreateLoad(layout.type->getElementType(field), address, "pyobf.frame.value");
            };
            auto *destination = read(layout.target);
            std::vector<llvm::Value *> arguments;
            for (const auto field : layout.arguments) arguments.push_back(read(field));
            auto *invoke = builder.CreateCall(call.getFunctionType(), destination, arguments);
            invoke->setCallingConv(call.getCallingConv());
            invoke->setAttributes(call.getAttributes());
            invoke->copyFastMathFlags(&call);
            invoke->setMetadata(llvm::LLVMContext::MD_prof, frame_profiles(call).inner);
            invoke->setMetadata("pyobf.frame.inner", descriptor);
            if (!call.getType()->isVoidTy()) {
                auto *result = builder.CreateStructGEP(layout.type, helper->getArg(0), layout.result);
                auto *store = builder.CreateStore(invoke, result);
                store->setMetadata("pyobf.frame.return-store", descriptor);
            }
            builder.CreateRetVoid();
            call.setMetadata("pyobf.frame.plan", descriptor);
            module.getOrInsertNamedMetadata("pyobf.frame.inventory")->addOperand(llvm::MDNode::get(context, {
                descriptor, llvm::ValueAsMetadata::get(owner), llvm::MDString::get(context, identity)}));
            GeneratedDefinition definition{helper, name, identity, component.str(), {}};
            if (prepared.count(&call)) {
                definition.support.components["call-preparation"] = Requirement::required;
                definition.support.max_preparation_steps = recipe.max_preparation_steps;
                definition.support.max_body_blocks = recipe.max_body_blocks;
                module.getOrInsertNamedMetadata("pyobf.prep.inventory")->addOperand(llvm::MDNode::get(context, {
                    descriptor, llvm::ValueAsMetadata::get(owner), llvm::MDString::get(context, identity)}));
            }
            generated.push_back(std::move(definition));
        }
    }
}

void plan_call_frames(llvm::Module &module, const std::map<std::string, ResolvedRecipe> &recipes,
                        std::vector<GeneratedDefinition> &generated) {
    plan_frame_component(module, recipes, generated, "call-frames");
}

}  // namespace pyobfuscator::native::cff
