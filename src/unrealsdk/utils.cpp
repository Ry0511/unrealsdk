#include "unrealsdk/pch.h"

#include "unrealsdk/utils.h"

namespace unrealsdk::utils {

static_assert(sizeof(wchar_t) == sizeof(char16_t), "wchar_t is different size to char16_t");

std::string narrow(std::wstring_view wstr) {
    if (wstr.empty()) {
        return {};
    }

    auto num_chars = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
                                         nullptr, 0, nullptr, nullptr);
    std::string ret(num_chars, '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), ret.data(),
                            num_chars, nullptr, nullptr)
        != num_chars) {
        throw std::runtime_error("Failed to convert utf16 string!");
    }

    return ret;
}

std::wstring widen(std::string_view str) {
    if (str.empty()) {
        return {};
    }

    auto num_chars =
        MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    std::wstring ret(num_chars, '\0');

    if (MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), ret.data(),
                            num_chars)
        != num_chars) {
        throw std::runtime_error("Failed to convert utf8 string!");
    }

    return ret;
}

namespace {

/**
 * @brief Gets the path of a module.
 *
 * @param module The module to get the path of.
 * @return The module's path.
 */
std::filesystem::path get_module_path(HMODULE module) {
    // Use wchars here since it's the native path type on Windows, so won't need a conversion
    wchar_t buf[MAX_PATH];
    auto num_chars = GetModuleFileNameW(module, &buf[0], ARRAYSIZE(buf));
    if (num_chars == 0) {
        throw std::runtime_error("Failed to get get module filename!");
    }

    auto begin = &buf[0];
    return {begin, begin + num_chars};
}

/**
 * @brief Get a handle to the module this function is compiled into.
 * @note Does not increase the refcount.
 *
 * @return A handle to this module
 */
HMODULE get_this_module(void) {
    HMODULE this_module = nullptr;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&get_this_module), &this_module)
        == 0) {
        throw std::runtime_error("Failed to get this module's handle!");
    }
    return this_module;
}

}  // namespace

std::filesystem::path get_this_dll(void) {
    static const std::filesystem::path path = get_module_path(get_this_module());
    return path;
}

std::filesystem::path get_executable(void) {
    static const std::filesystem::path path = get_module_path(nullptr);
    return path;
}

}  // namespace unrealsdk::utils
