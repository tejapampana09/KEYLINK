#include "CredentialProvider.h"
#include "CredentialProviderCredential.h"
#include "guid.h"
#include "helpers.h"
#include <new>

CCredentialProvider::CCredentialProvider() :
    _cRef(1),
    _usageScenario(CPUS_INVALID),
    _pCredential(NULL),
    _pEvents(NULL),
    _upAdviseContext(0) {
}

CCredentialProvider::~CCredentialProvider() {
    if (_pCredential) {
        _pCredential->Terminate();
        _pCredential->Release();
        _pCredential = NULL;
    }
    if (_pEvents) {
        _pEvents->Release();
        _pEvents = NULL;
    }
}

// IUnknown Implementation
IFACEMETHODIMP CCredentialProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = NULL;

    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CCredentialProvider::AddRef() {
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CCredentialProvider::Release() {
    ULONG cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

// ICredentialProvider Implementation
IFACEMETHODIMP CCredentialProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) {
    UNREFERENCED_PARAMETER(dwFlags);
    _usageScenario = cpus;

    // We support Logon, Unlock, and Cred UI scenarios
    if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION || cpus == CPUS_CREDUI) {
        if (_pCredential) {
            _pCredential->Terminate();
            _pCredential->Release();
            _pCredential = NULL;
        }

        // Allocate our UI tile instance
        _pCredential = new (std::nothrow) CCredentialProviderCredential(this, cpus);
        if (!_pCredential) {
            return E_OUTOFMEMORY;
        }
        
        // Initialize the pipe client thread in the credential
        _pCredential->Initialize();
        return S_OK;
    }

    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) {
    UNREFERENCED_PARAMETER(pcpcs);
    // Serialization set from a previous LogonUI session, not used in prototype
    return S_OK;
}

IFACEMETHODIMP CCredentialProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pfAutoLogonWithDefault) {
    if (!pdwCount || !pdwDefault || !pfAutoLogonWithDefault) {
        return E_POINTER;
    }

    // We expose exactly 1 credential tile
    *pdwCount = 1;
    *pdwDefault = 0;
    // When BLE auth has succeeded, tell LogonUI to automatically select & submit our tile
    *pfAutoLogonWithDefault = (_pCredential && _pCredential->IsAuthSucceeded()) ? TRUE : FALSE;
    return S_OK;
}

IFACEMETHODIMP CCredentialProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) {
    if (!ppcpc) return E_POINTER;
    *ppcpc = NULL;

    if (dwIndex == 0 && _pCredential) {
        HRESULT hr = _pCredential->QueryInterface(IID_ICredentialProviderCredential, (void**)ppcpc);
        return hr;
    }

    return E_INVALIDARG;
}

IFACEMETHODIMP CCredentialProvider::GetFieldDescriptorCount(DWORD* pdwCount) {
    if (!pdwCount) return E_POINTER;
    *pdwCount = 3; // Logo (Image), Title (Large Text), Status (Small Text)
    return S_OK;
}

IFACEMETHODIMP CCredentialProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    if (!ppcpfd) return E_POINTER;
    *ppcpfd = NULL;

    if (dwIndex >= 3) return E_INVALIDARG;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!pcpfd) return E_OUTOFMEMORY;

    // Field descriptions are queried by LogonUI. We must allocate the strings using CoTaskMemAlloc.
    // Note: Member is named dwFieldID (capital ID) in the SDK.
    switch (dwIndex) {
        case 0: // FID_LOGO (Large tile image icon)
            pcpfd->dwFieldID = 0;
            pcpfd->cpft = CPFT_TILE_IMAGE;
            CopyCoTaskMemString(L"KeyLink Logo", &pcpfd->pszLabel);
            pcpfd->guidFieldType = GUID_NULL;
            break;
        case 1: // FID_TITLE (Header text)
            pcpfd->dwFieldID = 1;
            pcpfd->cpft = CPFT_LARGE_TEXT;
            CopyCoTaskMemString(L"KeyLink Verification", &pcpfd->pszLabel);
            pcpfd->guidFieldType = GUID_NULL;
            break;
        case 2: // FID_STATUS (Interactive status label)
            pcpfd->dwFieldID = 2;
            pcpfd->cpft = CPFT_SMALL_TEXT;
            CopyCoTaskMemString(L"Authentication Status", &pcpfd->pszLabel);
            pcpfd->guidFieldType = GUID_NULL;
            break;
    }

    *ppcpfd = pcpfd;
    return S_OK;
}

IFACEMETHODIMP CCredentialProvider::Advise(ICredentialProviderEvents* pEvents, ULONG_PTR upAdviseContext) {
    if (_pEvents) {
        _pEvents->Release();
        _pEvents = NULL;
    }

    _pEvents = pEvents;
    _upAdviseContext = upAdviseContext;

    if (_pEvents) {
        _pEvents->AddRef();
    }
    return S_OK;
}

IFACEMETHODIMP CCredentialProvider::UnAdvise() {
    if (_pEvents) {
        _pEvents->Release();
        _pEvents = NULL;
    }
    _upAdviseContext = 0;
    return S_OK;
}
