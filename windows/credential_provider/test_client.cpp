#include <windows.h>
#include <credentialprovider.h>
#include <iostream>
#include <string>
#include "guid.h"
#include "helpers.h"

// Mock implementation of ICredentialProviderCredentialEvents to capture DLL in-place field updates
class CMockCredentialProviderCredentialEvents : public ICredentialProviderCredentialEvents {
public:
    CMockCredentialProviderCredentialEvents() : _cRef(1), _triggered(false) {}
    
    virtual ~CMockCredentialProviderCredentialEvents() {}

    // IUnknown methods
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredentialEvents) {
            *ppv = static_cast<ICredentialProviderCredentialEvents*>(this);
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

    // ICredentialProviderCredentialEvents methods
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential* pcpc, DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE cpfs) {
        UNREFERENCED_PARAMETER(pcpc);
        UNREFERENCED_PARAMETER(dwFieldID);
        UNREFERENCED_PARAMETER(cpfs);
        return S_OK;
    }

    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential* pcpc, DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis) {
        UNREFERENCED_PARAMETER(pcpc);
        UNREFERENCED_PARAMETER(dwFieldID);
        UNREFERENCED_PARAMETER(cpfis);
        return S_OK;
    }

    // This is the in-place status field update we are checking!
    IFACEMETHODIMP SetFieldString(ICredentialProviderCredential* pcpc, DWORD dwFieldID, PCWSTR psz) {
        UNREFERENCED_PARAMETER(pcpc);
        if (dwFieldID == 2) { // FID_STATUS
            std::wstring status(psz);
            _lastStatus = status;
            _triggered = true;
        }
        return S_OK;
    }

    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential* pcpc, DWORD dwFieldID, BOOL bChecked, PCWSTR pszLabel) {
        UNREFERENCED_PARAMETER(pcpc);
        UNREFERENCED_PARAMETER(dwFieldID);
        UNREFERENCED_PARAMETER(bChecked);
        UNREFERENCED_PARAMETER(pszLabel);
        return S_OK;
    }

    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential* pcpc, DWORD dwFieldID, HBITMAP hbmp) {
        UNREFERENCED_PARAMETER(pcpc);
        UNREFERENCED_PARAMETER(dwFieldID);
        UNREFERENCED_PARAMETER(hbmp);
        return S_OK;
    }

    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential* pcpc, DWORD dwFieldID, DWORD dwSelectedItem) {
        UNREFERENCED_PARAMETER(pcpc);
        UNREFERENCED_PARAMETER(dwFieldID);
        UNREFERENCED_PARAMETER(dwSelectedItem);
        return S_OK;
    }

    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential* pcpc, DWORD dwFieldID, DWORD dwItem) {
        UNREFERENCED_PARAMETER(pcpc);
        UNREFERENCED_PARAMETER(dwFieldID);
        UNREFERENCED_PARAMETER(dwItem);
        return S_OK;
    }

    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential* pcpc, DWORD dwFieldID, PCWSTR pszItem) {
        UNREFERENCED_PARAMETER(pcpc);
        UNREFERENCED_PARAMETER(dwFieldID);
        UNREFERENCED_PARAMETER(pszItem);
        return S_OK;
    }

    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential* pcpc, DWORD dwFieldID, DWORD dwAdjacentTo) {
        UNREFERENCED_PARAMETER(pcpc);
        UNREFERENCED_PARAMETER(dwFieldID);
        UNREFERENCED_PARAMETER(dwAdjacentTo);
        return S_OK;
    }

    IFACEMETHODIMP OnCreatingWindow(HWND* phwndOwner) {
        UNREFERENCED_PARAMETER(phwndOwner);
        return S_OK;
    }

    bool HasBeenTriggered(std::wstring& outStatus) {
        if (_triggered) {
            outStatus = _lastStatus;
            _triggered = false;
            return true;
        }
        return false;
    }

private:
    long _cRef;
    bool _triggered;
    std::wstring _lastStatus;
};

// Mock implementation of ICredentialProviderEvents (provider level, not used for field updates anymore)
class CMockCredentialProviderEvents : public ICredentialProviderEvents {
public:
    CMockCredentialProviderEvents() : _cRef(1) {}
    virtual ~CMockCredentialProviderEvents() {}

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderEvents) {
            *ppv = static_cast<ICredentialProviderEvents*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&_cRef); }
    IFACEMETHODIMP_(ULONG) Release() {
        ULONG cRef = InterlockedDecrement(&_cRef);
        if (cRef == 0) delete this;
        return cRef;
    }

    IFACEMETHODIMP CredentialsChanged(ULONG_PTR upAdviseContext) {
        UNREFERENCED_PARAMETER(upAdviseContext);
        return S_OK;
    }

private:
    long _cRef;
};

typedef HRESULT(WINAPI* LPFNDLLGETCLASSOBJECT)(REFCLSID, REFIID, LPVOID*);

int main() {
    std::cout << "=== KEYLINK CREDENTIAL PROVIDER DLL RUNTIME TESTER ===" << std::endl;

    // 1. Dynamically load the DLL
    std::wstring dllPath = L"KeyLinkProvider.dll";
    std::wcout << L"Loading library: " << dllPath << std::endl;
    HMODULE hDll = LoadLibraryW(dllPath.c_str());
    if (!hDll) {
        std::cerr << "Error: Failed to load KeyLinkProvider.dll. Verify it is compiled." << std::endl;
        return 1;
    }
    std::cout << "Success: DLL loaded successfully!" << std::endl;

    // 2. Retrieve DllGetClassObject function pointer
    FARPROC procAddress = GetProcAddress(hDll, "DllGetClassObject");
    LPFNDLLGETCLASSOBJECT pfnDllGetClassObject = reinterpret_cast<LPFNDLLGETCLASSOBJECT>(reinterpret_cast<void*>(procAddress));
    if (!pfnDllGetClassObject) {
        std::cerr << "Error: Failed to find DllGetClassObject export." << std::endl;
        FreeLibrary(hDll);
        return 1;
    }

    // 3. Retrieve Class Factory
    IClassFactory* pFactory = nullptr;
    HRESULT hr = pfnDllGetClassObject(CLSID_KeyLinkProvider, IID_IClassFactory, (void**)&pFactory);
    if (FAILED(hr)) {
        std::cerr << "Error: DllGetClassObject failed (HRESULT: " << hr << ")" << std::endl;
        FreeLibrary(hDll);
        return 1;
    }

    // 4. Create ICredentialProvider instance
    ICredentialProvider* pProvider = nullptr;
    hr = pFactory->CreateInstance(nullptr, IID_ICredentialProvider, (void**)&pProvider);
    pFactory->Release();
    if (FAILED(hr)) {
        std::cerr << "Error: Failed to create ICredentialProvider instance." << std::endl;
        FreeLibrary(hDll);
        return 1;
    }
    std::cout << "Success: COM ICredentialProvider instantiated!" << std::endl;

    // 5. Register Mock Event listener for Provider
    CMockCredentialProviderEvents* pMockEvents = new CMockCredentialProviderEvents();
    hr = pProvider->Advise(pMockEvents, 42);
    if (FAILED(hr)) {
        std::cerr << "Error: Advise failed." << std::endl;
        pProvider->Release();
        pMockEvents->Release();
        FreeLibrary(hDll);
        return 1;
    }

    // 6. Set scenario to CPUS_UNLOCK_WORKSTATION
    std::cout << "Initializing scenario: CPUS_UNLOCK_WORKSTATION..." << std::endl;
    hr = pProvider->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0);
    if (FAILED(hr)) {
        std::cerr << "Error: SetUsageScenario failed." << std::endl;
        pProvider->UnAdvise();
        pProvider->Release();
        pMockEvents->Release();
        FreeLibrary(hDll);
        return 1;
    }

    // 7. Retrieve the credential tile
    DWORD dwCount = 0, dwDefault = 0;
    BOOL fAutoLogon = FALSE;
    pProvider->GetCredentialCount(&dwCount, &dwDefault, &fAutoLogon);
    std::cout << "Provider reports tile count: " << dwCount << std::endl;

    if (dwCount < 1) {
        std::cerr << "Error: Provider did not enumerate any credential tiles." << std::endl;
        pProvider->UnAdvise();
        pProvider->Release();
        pMockEvents->Release();
        FreeLibrary(hDll);
        return 1;
    }

    ICredentialProviderCredential* pCredential = nullptr;
    hr = pProvider->GetCredentialAt(0, &pCredential);
    if (FAILED(hr)) {
        std::cerr << "Error: Failed to get credential tile at index 0." << std::endl;
        pProvider->UnAdvise();
        pProvider->Release();
        pMockEvents->Release();
        FreeLibrary(hDll);
        return 1;
    }

    // 8. Register Mock Credential Event listener for in-place label updates
    CMockCredentialProviderCredentialEvents* pMockCredEvents = new CMockCredentialProviderCredentialEvents();
    hr = pCredential->Advise(pMockCredEvents);
    if (FAILED(hr)) {
        std::cerr << "Error: Credential Advise failed." << std::endl;
        pCredential->Release();
        pProvider->UnAdvise();
        pProvider->Release();
        pMockEvents->Release();
        pMockCredEvents->Release();
        FreeLibrary(hDll);
        return 1;
    }
    std::cout << "Success: Credential events Advise complete!" << std::endl;

    std::cout << "\n==============================================" << std::endl;
    std::cout << "TEST RUNNING. Listening to pipe \\\\.\\pipe\\KeyLinkLogonPipe..." << std::endl;
    std::cout << "Use the mock_pipe_server.py script to write states." << std::endl;
    std::cout << "Press Ctrl+C in this terminal to exit." << std::endl;
    std::cout << "==============================================" << std::endl;

    // 9. Poll and display the status field string value
    try {
        PWSTR ppszStatus = nullptr;
        // Print initial status
        if (SUCCEEDED(pCredential->GetStringValue(2, &ppszStatus))) { // 2 = FID_STATUS
            std::wcout << L"Current status: " << ppszStatus << std::endl;
            CoTaskMemFree(ppszStatus);
        }

        while (true) {
            Sleep(100);
            std::wstring newStatus;
            if (pMockCredEvents->HasBeenTriggered(newStatus)) {
                std::wcout << L"[UI Refresh - In-place] Status changed to: " << newStatus << std::endl;
            }
        }
    } catch (...) {
        // Handle exit
    }

    // Cleanup
    pCredential->UnAdvise();
    pCredential->Release();
    pProvider->UnAdvise();
    pProvider->Release();
    pMockEvents->Release();
    pMockCredEvents->Release();
    FreeLibrary(hDll);
    return 0;
}
