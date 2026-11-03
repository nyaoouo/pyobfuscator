#include "pyobfuscator_native/system_ops.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <limits>

namespace pyobfuscator::native::platform {

namespace {

struct LoadedImage {
    HMODULE module;
    wchar_t path[MAX_PATH];
};

bool write_all(HANDLE file, const std::uint8_t *bytes, std::size_t length) noexcept {
    while (length != 0) {
        const auto chunk = static_cast<DWORD>(
            length < (std::numeric_limits<DWORD>::max)() ? length :
                                                         (std::numeric_limits<DWORD>::max)());
        DWORD written = 0;
        if (!WriteFile(file, bytes, chunk, &written, nullptr) || written == 0) {
            return false;
        }
        bytes += written;
        length -= written;
    }
    return true;
}

}  // namespace

void *load_payload(const std::uint8_t *bytes, std::size_t length) noexcept {
    auto *image = static_cast<LoadedImage *>(allocate(sizeof(LoadedImage)));
    if (image == nullptr) {
        return nullptr;
    }
    image->module = nullptr;
    wchar_t directory[MAX_PATH];
    const DWORD directory_length = GetTempPathW(MAX_PATH, directory);
    if (directory_length == 0 || directory_length >= MAX_PATH ||
        GetTempFileNameW(directory, L"pob", 0, image->path) == 0) {
        release(image);
        return nullptr;
    }

    HANDLE file = CreateFileW(image->path, GENERIC_WRITE, 0, nullptr, TRUNCATE_EXISTING,
                              FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        DeleteFileW(image->path);
        release(image);
        return nullptr;
    }
    const bool written = write_all(file, bytes, length);
    const bool closed = CloseHandle(file) != 0;
    if (!written || !closed) {
        DeleteFileW(image->path);
        release(image);
        return nullptr;
    }
    image->module = LoadLibraryW(image->path);
    if (image->module == nullptr) {
        DeleteFileW(image->path);
        release(image);
        return nullptr;
    }
    return image;
}

void *resolve_payload_entry(void *opaque_image) noexcept {
    auto *image = static_cast<LoadedImage *>(opaque_image);
    return image == nullptr ? nullptr :
        reinterpret_cast<void *>(GetProcAddress(image->module, "pyobf_native_inner_entry"));
}

void unload_payload(void *opaque_image) noexcept {
    auto *image = static_cast<LoadedImage *>(opaque_image);
    if (image == nullptr) {
        return;
    }
    if (image->module != nullptr) {
        FreeLibrary(image->module);
    }
    DeleteFileW(image->path);
    release(image);
}

}  // namespace pyobfuscator::native::platform
