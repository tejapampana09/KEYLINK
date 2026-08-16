#include <windows.h>
#include <unknwn.h>
#include <new>
#include <string>
#include "guid.h"
#include "CredentialProvider.h"

HINSTANCE g_hInst = NULL;
long g_cRefModule = 0;

// Standard Class Factory for COM
class CClassFactory : public IClassFactory {
public:
    // IUnknown methods
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release() {
        ULONG cRef = InterlockedDecrement(&_cRef);
        if (cRef == 0) {
            delete this;
        }
        return cRef;
    }

    // IClassFactory methods
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;

        CCredentialProvider* pProvider = new (std::nothrow) CCredentialProvider();
        if (!pProvider) return E_OUTOFMEMORY;

        HRESULT hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL fLock) {
        if (fLock) {
            InterlockedIncrement(&g_cRefModule);
        } else {
            InterlockedDecrement(&g_cRefModule);
        }
        return S_OK;
    }

    CClassFactory() : _cRef(1) {
        InterlockedIncrement(&g_cRefModule);
    }

protected:
    virtual ~CClassFactory() {
        InterlockedDecrement(&g_cRefModule);
    }

private:
    long _cRef;
};

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hInst = hModule;
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

// Retrieves the Class Factory object for our CLSID
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = NULL;

    if (rclsid == CLSID_KeyLinkProvider) {
        CClassFactory* pFactory = new (std::nothrow) CClassFactory();
        if (!pFactory) return E_OUTOFMEMORY;
        HRESULT hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

// Tells Windows if the DLL can be safely unloaded from memory
STDAPI DllCanUnloadNow(void) {
    return (g_cRefModule == 0) ? S_OK : S_FALSE;
}

// Helper to write keys to registry for COM registration
HRESULT RegisterKey(HKEY hKeyParent, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR valueData) {
    HKEY hKey;
    LONG result = RegCreateKeyExW(hKeyParent, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (result == ERROR_SUCCESS) {
        if (valueData) {
            result = RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)valueData, (DWORD)(wcslen(valueData) + 1) * sizeof(wchar_t));
        }
        RegCloseKey(hKey);
    }
    return HRESULT_FROM_WIN32(result);
}

// Self-Registration entrypoint (regsvr32 KeyLinkProvider.dll)
STDAPI DllRegisterServer(void) {
    wchar_t szModule[MAX_PATH];
    if (!GetModuleFileNameW(g_hInst, szModule, MAX_PATH)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    wchar_t szCLSID[128];
    StringFromGUID2(CLSID_KeyLinkProvider, szCLSID, 128);

    std::wstring subKeyClsid = L"CLSID\\" + std::wstring(szCLSID);
    HRESULT hr = RegisterKey(HKEY_CLASSES_ROOT, subKeyClsid.c_str(), NULL, L"KeyLink Credential Provider");
    if (SUCCEEDED(hr)) {
        std::wstring subKeyInproc = subKeyClsid + L"\\InprocServer32";
        hr = RegisterKey(HKEY_CLASSES_ROOT, subKeyInproc.c_str(), NULL, szModule);
        if (SUCCEEDED(hr)) {
            hr = RegisterKey(HKEY_CLASSES_ROOT, subKeyInproc.c_str(), L"ThreadingModel", L"Apartment");
        }
    }

    if (SUCCEEDED(hr)) {
        std::wstring subKeyProvider = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" + std::wstring(szCLSID);
        hr = RegisterKey(HKEY_LOCAL_MACHINE, subKeyProvider.c_str(), NULL, L"KeyLinkProvider");
    }

    return hr;
}

// Self-Unregistration entrypoint (regsvr32 /u KeyLinkProvider.dll)
STDAPI DllUnregisterServer(void) {
    wchar_t szCLSID[128];
    StringFromGUID2(CLSID_KeyLinkProvider, szCLSID, 128);

    std::wstring subKeyClsid = L"CLSID\\" + std::wstring(szCLSID);
    
    std::wstring subKeyInproc = subKeyClsid + L"\\InprocServer32";
    RegDeleteKeyW(HKEY_CLASSES_ROOT, subKeyInproc.c_str());
    RegDeleteKeyW(HKEY_CLASSES_ROOT, subKeyClsid.c_str());

    std::wstring subKeyProvider = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" + std::wstring(szCLSID);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, subKeyProvider.c_str());

    return S_OK;
}
