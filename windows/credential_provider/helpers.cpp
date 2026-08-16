#include "helpers.h"
#include <vector>

std::wstring Utf8ToUtf16(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), NULL, 0);
    std::wstring utf16(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &utf16[0], sizeNeeded);
    return utf16;
}

std::string Utf16ToUtf8(const std::wstring& utf16) {
    if (utf16.empty()) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), (int)utf16.size(), NULL, 0, NULL, NULL);
    std::string utf8(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), (int)utf16.size(), &utf8[0], sizeNeeded, NULL, NULL);
    return utf8;
}

HRESULT CopyCoTaskMemString(const std::wstring& src, PWSTR* dest) {
    if (!dest) return E_POINTER;
    size_t sizeBytes = (src.length() + 1) * sizeof(wchar_t);
    *dest = (PWSTR)CoTaskMemAlloc(sizeBytes);
    if (!*dest) return E_OUTOFMEMORY;
    wcscpy_s(*dest, src.length() + 1, src.c_str());
    return S_OK;
}
