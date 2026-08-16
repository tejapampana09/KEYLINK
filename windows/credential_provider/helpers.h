#pragma once
#include <windows.h>
#include <string>

// Converts a UTF-8 string to a UTF-16 wide string
std::wstring Utf8ToUtf16(const std::string& utf8);

// Converts a UTF-16 wide string to a UTF-8 string
std::string Utf16ToUtf8(const std::wstring& utf16);

// Safely duplicates a wide string using CoTaskMemAlloc (required for LogonUI string fields)
HRESULT CopyCoTaskMemString(const std::wstring& src, PWSTR* dest);
