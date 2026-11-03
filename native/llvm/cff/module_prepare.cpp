#include "module_prepare.hpp"
#include "site_report.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {

std::map<std::string, GeneratedDefinition> prepare_module_components(
    llvm::Module &module, std::map<std::string, ResolvedRecipe> &recipes, unsigned seed) {
    std::vector<GeneratedDefinition> generated;
    std::set<const llvm::Function *> original_definitions;
    for (const auto &function : module) if (!function.isDeclaration()) original_definitions.insert(&function);
    const auto original_recipes = recipes;
    for (const auto &[name, recipe] : original_recipes)
        if (auto *function = module.getFunction(name); function != nullptr && !function->isDeclaration())
            stamp_site_provenance(*function, "input");
    for (const auto &component : registered_components())
        if (component.module_prepare != nullptr) component.module_prepare(module, original_recipes, generated);
    std::map<std::string, GeneratedDefinition> result;
    for (auto &definition : generated) {
        if (definition.function == nullptr || definition.site.empty() || find_component(definition.component) == nullptr)
            llvm::report_fatal_error("native generated helper has an invalid definition contract");
        const auto name = definition.function->getName().str();
        if (definition.function->getParent() != &module || definition.function->isDeclaration() ||
            !definition.function->hasInternalLinkage() || !original_recipes.count(definition.owner) ||
            original_definitions.count(definition.function) || recipes.count(name) || !result.emplace(name, definition).second)
            llvm::report_fatal_error("native generated helper has invalid ownership or a selection collision");
        if (!definition.support.recipe.empty()) llvm::report_fatal_error("native helper support cannot reset its baseline recipe");
        if (definition.support.coverage && *definition.support.coverage != "whole")
            llvm::report_fatal_error("native generated helper requires whole coverage");
        for (const auto &[component, requirement] : definition.support.components)
            if (component == definition.component || find_component(component) == nullptr ||
                !original_recipes.at(definition.owner).enabled(component))
                llvm::report_fatal_error("native generated helper requested unavailable or recursive support");
        RecipeConfiguration support;
        support.defaults = definition.support;
        recipes.emplace(name, resolve_recipe(support, name, {}, "relative-tree", false, false, seed, true));
    }
    for (const auto &function : module) if (!function.isDeclaration()) {
        if (original_definitions.erase(&function)) continue;
        if (!result.count(function.getName().str()))
            llvm::report_fatal_error("native module component generated an unregistered definition");
    }
    if (!original_definitions.empty()) llvm::report_fatal_error("native module component removed an original definition");
    return result;
}

}  // namespace pyobfuscator::native::cff
