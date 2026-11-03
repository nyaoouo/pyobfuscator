#include "internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::detail {

PYOBF_NATIVE_CFF_SDK Status validate(const Descriptor &input, const ModuleView *view,
        std::size_t &material_size) noexcept {
    material_size = 0;
    if (input.kind != 1 && input.kind != 2 && input.kind != 3) return Status::unsupported;
    if (input.subject == 0 || input.owner == 0 || input.image_size < 64 || input.ranges == nullptr ||
            input.range_count == 0 || input.range_count > max_ranges || input.fixup_count > max_fixups ||
            (input.fixup_count && input.fixups == nullptr) || input.preferred_base > UINT64_MAX - input.image_size)
        return Status::invalid_descriptor;
    if (view != nullptr) {
        if (view->lease.module == nullptr || view->base == nullptr || view->loaded_base == 0 ||
                view->image_size < 64 || view->loaded_base > UINT64_MAX - view->image_size ||
                view->section_count == 0 || view->section_count > 96) return Status::unavailable;
        // Windows may rewrite the mapped header's ImageBase; it is not the link origin.
        if (input.image_size != view->image_size ||
                (view->header_base != input.preferred_base && view->header_base != view->loaded_base))
            return Status::invalid_descriptor;
    }
    std::uint64_t total = 0, previous_end = 0;
    for (std::uint32_t index = 0; index != input.range_count; ++index) {
        const auto range = input.ranges[index];
        if (range.size == 0 || range.rva < previous_end || range.rva > input.image_size ||
                range.size > input.image_size - range.rva) return Status::invalid_descriptor;
        previous_end = std::uint64_t(range.rva) + range.size;
        total += range.size;
        if (total > max_subject_bytes) return Status::invalid_descriptor;
    }
    previous_end = 0;
    for (std::uint32_t index = 0; index != input.fixup_count; ++index) {
        const auto target = input.fixups[index];
        if (target < previous_end || target > input.image_size || input.image_size - target < 8)
            return Status::invalid_descriptor;
        previous_end = std::uint64_t(target) + 8;
        if (view != nullptr) {
            unsigned matches = 0;
            for (std::uint32_t section = 0; section != view->section_count; ++section) {
                const auto &range = view->sections[section];
                if (target >= range.rva && target - range.rva <= range.mapped_size &&
                        8 <= range.mapped_size - (target - range.rva)) ++matches;
            }
            if (matches != 1) return Status::invalid_descriptor;
        }
        for (std::uint32_t range = 0; range != input.range_count; ++range) {
            const auto span = input.ranges[range];
            const auto end = std::uint64_t(span.rva) + span.size;
            if (target >= end || std::uint64_t(target) + 8 <= span.rva) continue;
            if (target < span.rva || std::uint64_t(target) + 8 > end) return Status::invalid_descriptor;
        }
    }
    material_size = sizeof(domain) + 20 + input.range_count * 8 + static_cast<std::size_t>(total);
    return Status::ok;
}

}  // namespace pyobfuscator::native::measurement::detail
