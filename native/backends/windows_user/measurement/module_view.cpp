#include "measurement/backend.hpp"

#define WIN32_LEAN_AND_MEAN
#ifdef PSAPI_VERSION
#undef PSAPI_VERSION
#endif
#define PSAPI_VERSION 2
#include <windows.h>
#include <psapi.h>

namespace pyobfuscator::native::platform {
namespace {
using measurement::ModuleView;
using measurement::Status;

const volatile std::uint8_t *mapped_span(const ModuleView &view, std::uint32_t rva,
        std::uint32_t size, bool executable) noexcept {
    if (view.lease.module == nullptr || view.base == nullptr || size == 0 ||
            rva > view.image_size || size > view.image_size - rva) return nullptr;
    auto address = view.loaded_base + rva;
    const auto end = address + size;
    while (address < end) {
        MEMORY_BASIC_INFORMATION region{};
        if (VirtualQuery(reinterpret_cast<const void *>(address), &region, sizeof(region)) != sizeof(region) ||
                region.AllocationBase != view.lease.module || region.Type != MEM_IMAGE || region.State != MEM_COMMIT ||
                region.Protect & PAGE_GUARD) return nullptr;
        const auto protection = region.Protect & 0xffu;
        if (executable ? protection != PAGE_EXECUTE_READ :
                (protection != PAGE_READONLY && protection != PAGE_READWRITE && protection != PAGE_WRITECOPY &&
                 protection != PAGE_EXECUTE_READ && protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY))
            return nullptr;
        const auto begin = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        if (begin > address || region.RegionSize == 0 || region.RegionSize > UINTPTR_MAX - begin) return nullptr;
        const auto next = begin + region.RegionSize;
        if (next <= address) return nullptr;
        address = next < end ? next : end;
    }
    return view.base + rva;
}

std::uint64_t number(const volatile std::uint8_t *source, unsigned width) noexcept {
    std::uint64_t value = 0;
    for (unsigned index = 0; index != width; ++index) value |= std::uint64_t(source[index]) << (index * 8);
    return value;
}

Status inspect(ModuleView &view) noexcept {
    const auto *dos = mapped_span(view, 0, 64, false);
    if (dos == nullptr || number(dos, 2) != 0x5a4d) return Status::unsupported;
    const auto pe = number(dos + 60, 4);
    if (pe < 64 || pe > view.image_size || view.image_size - pe < 24) return Status::unsupported;
    const auto *coff = mapped_span(view, static_cast<std::uint32_t>(pe), 24, false);
    if (coff == nullptr || number(coff, 4) != 0x4550 || number(coff + 4, 2) != 0x8664) return Status::unsupported;
    const auto sections = number(coff + 6, 2), optional_size = number(coff + 20, 2);
    const auto flags = number(coff + 22, 2);
    if (sections == 0 || sections > 96 || optional_size < 112 || !(flags & 2) || flags & 0x1000)
        return Status::unsupported;
    const auto optional = pe + 24;
    if (optional_size > view.image_size - optional) return Status::unsupported;
    const auto *header = mapped_span(view, static_cast<std::uint32_t>(optional), static_cast<std::uint32_t>(optional_size), false);
    if (header == nullptr || number(header, 2) != 0x20b || number(header + 56, 4) != view.image_size)
        return Status::unsupported;
    const auto directories = number(header + 108, 4);
    const auto table = optional + optional_size;
    const auto headers_size = number(header + 60, 4);
    if (directories > 16 || 112 + directories * 8 > optional_size || table > headers_size ||
            sections * 40 > headers_size - table || headers_size > view.image_size) return Status::unsupported;
    const auto *rows = mapped_span(view, static_cast<std::uint32_t>(table), static_cast<std::uint32_t>(sections * 40), false);
    if (rows == nullptr) return Status::unsupported;
    view.header_base = number(header + 24, 8);
    if (view.header_base > UINT64_MAX - view.image_size) return Status::unsupported;
    for (std::uint32_t index = 0; index != sections; ++index) {
        const auto *row = rows + index * 40;
        const auto virtual_size = number(row + 8, 4), raw_size = number(row + 16, 4);
        const auto rva = number(row + 12, 4), size = virtual_size ? virtual_size : raw_size;
        const auto mapped_size = virtual_size > raw_size ? virtual_size : raw_size;
        if (rva > view.image_size || mapped_size > view.image_size - rva || (mapped_size && rva < headers_size))
            return Status::unsupported;
        view.sections[index] = {static_cast<std::uint32_t>(rva), static_cast<std::uint32_t>(size),
            static_cast<std::uint32_t>(mapped_size),
            static_cast<std::uint32_t>(number(row + 36, 4))};
        for (std::uint32_t other = 0; other != index; ++other) {
            const auto &previous = view.sections[other];
            if (mapped_size && previous.mapped_size && rva < std::uint64_t(previous.rva) + previous.mapped_size &&
                    previous.rva < rva + mapped_size) return Status::unsupported;
        }
    }
    view.section_count = static_cast<std::uint32_t>(sections);
    return Status::ok;
}
}

measurement::Status open_code_view(CodeAddress address, measurement::ModuleView &output) noexcept {
    if (output.lease.module != nullptr) return measurement::Status::invalid_descriptor;
    output = {};
    if (sizeof(void *) != 8) return measurement::Status::unsupported;
    output.lease = PYOBF_NATIVE_RETAIN_CODE(address);
    if (output.lease.module == nullptr) return measurement::Status::unavailable;
    MODULEINFO information{};
    measurement::Status status = measurement::Status::unavailable;
    if (K32GetModuleInformation(GetCurrentProcess(), static_cast<HMODULE>(output.lease.module), &information, sizeof(information)) &&
            information.lpBaseOfDll == output.lease.module && information.SizeOfImage >= 64) {
        output.base = static_cast<const std::uint8_t *>(information.lpBaseOfDll);
        output.loaded_base = reinterpret_cast<std::uintptr_t>(output.base);
        output.image_size = information.SizeOfImage;
        if (output.loaded_base <= UINT64_MAX - output.image_size) status = inspect(output);
    }
    if (status != measurement::Status::ok && !close_code_view(output)) PYOBF_NATIVE_PROTECTION_FAILURE(0x701);
    return status;
}

bool close_code_view(measurement::ModuleView &view) noexcept {
    if (!PYOBF_NATIVE_RELEASE_CODE(view.lease)) return false;
    view = {};
    return true;
}

const volatile std::uint8_t *code_span(const measurement::ModuleView &view,
        std::uint32_t rva, std::uint32_t size) noexcept {
    unsigned matches = 0;
    for (std::uint32_t index = 0; index != view.section_count; ++index) {
        const auto &section = view.sections[index];
        if ((section.flags & 0x60000000) == 0x60000000 && !(section.flags & 0x82000000) &&
                rva >= section.rva && rva - section.rva <= section.size && size <= section.size - (rva - section.rva))
            ++matches;
    }
    return matches == 1 ? mapped_span(view, rva, size, true) : nullptr;
}

}  // namespace pyobfuscator::native::platform
