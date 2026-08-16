#include "CredentialProviderCredential.h"
#include "CredentialProvider.h"
#include "helpers.h"
#include "guid.h"
#include <new>
#include <ntsecapi.h>
#include <wincred.h>
#include <credentialprovider.h>
#include <vector>
#include <sstream>

// Define layout fields for LogonUI
enum FIELD_ID {
    FID_LOGO = 0,
    FID_TITLE = 1,
    FID_STATUS = 2,
    FID_NUM_FIELDS = 3
};

CCredentialProviderCredential::CCredentialProviderCredential(CCredentialProvider* pProvider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) :
    _cRef(1),
    _pProvider(pProvider),
    _usageScenario(cpus),
    _statusText(L"Waiting for phone..."),
    _hPipeThread(NULL),
    _stopThread(false),
    _authSuccess(false),
    _pCredentialEvents(NULL) {
    
    _winUsername.clear();
    _winPasswordBlob.clear();
    
    if (_pProvider) {
        _pProvider->AddRef();
    }
    InitializeCriticalSection(&_csStatus);
}

CCredentialProviderCredential::~CCredentialProviderCredential() {
    Terminate();
    if (_pProvider) {
        _pProvider->Release();
        _pProvider = NULL;
    }
    if (_pCredentialEvents) {
        _pCredentialEvents->Release();
        _pCredentialEvents = NULL;
    }
    DeleteCriticalSection(&_csStatus);
}

void CCredentialProviderCredential::Initialize() {
    _stopThread = false;
    // Spawn the background named pipe client thread
    _hPipeThread = CreateThread(NULL, 0, PipeThreadProc, this, 0, NULL);
}

void CCredentialProviderCredential::Terminate() {
    _stopThread = true;
    if (_hPipeThread) {
        // Wait up to 1 second for the thread to gracefully exit
        WaitForSingleObject(_hPipeThread, 1000);
        CloseHandle(_hPipeThread);
        _hPipeThread = NULL;
    }
}

// IUnknown Implementation
IFACEMETHODIMP CCredentialProviderCredential::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = NULL;

    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CCredentialProviderCredential::AddRef() {
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CCredentialProviderCredential::Release() {
    ULONG cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

// ICredentialProviderCredential Implementation
IFACEMETHODIMP CCredentialProviderCredential::GetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO* pcpus) {
    if (!pcpus) return E_POINTER;
    *pcpus = _usageScenario;
    return S_OK;
}

IFACEMETHODIMP CCredentialProviderCredential::GetProviderGuid(GUID* pguidProvider) {
    if (!pguidProvider) return E_POINTER;
    *pguidProvider = CLSID_KeyLinkProvider;
    return S_OK;
}

IFACEMETHODIMP CCredentialProviderCredential::GetUserSid(PWSTR* ppszUserSid) {
    if (!ppszUserSid) return E_POINTER;
    *ppszUserSid = NULL; // Return NULL so our tile is displayed globally (or for current session)
    return S_OK;
}

// Forward declarations for static helpers defined later in this file
static std::vector<BYTE> Base64Decode(const std::string& in);

// CRED_PACK_PROTECTED_CREDENTIALS may be missing in older MinGW headers
#ifndef CRED_PACK_PROTECTED_CREDENTIALS
#define CRED_PACK_PROTECTED_CREDENTIALS 0x4
#endif

IFACEMETHODIMP CCredentialProviderCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {

    if (!pcpgsr || !pcpcs) return E_POINTER;

    if (_authSuccess.load() && !_winUsername.empty() && !_winPasswordBlob.empty()) {

        // Reconstruct plain-text password from stored UTF-16LE bytes
        std::wstring password(
            reinterpret_cast<const wchar_t*>(_winPasswordBlob.data()),
            _winPasswordBlob.size() / sizeof(wchar_t)
        );

        // For local accounts, prefix username with ".\\"
        // e.g. "ss" -> ".\\ss" so LSA resolves against the local machine SAM.
        std::wstring qualifiedUsername = L".\\" + _winUsername;

        // CredPackAuthenticationBuffer packs username+password into the correct
        // KERB_INTERACTIVE_UNLOCK_LOGON format that LogonUI/LSA expects.
        // Use flag 0 (plain) — CRED_PACK_PROTECTED_CREDENTIALS requires domain context
        // which is absent on local-account-only machines and causes ERROR_INVALID_PARAMETER.
        DWORD cbPacked = 0;
        // First call: get required buffer size
        CredPackAuthenticationBufferW(
            0,
            const_cast<LPWSTR>(qualifiedUsername.c_str()),
            const_cast<LPWSTR>(password.c_str()),
            NULL, &cbPacked);

        BYTE* pPacked = static_cast<BYTE*>(CoTaskMemAlloc(cbPacked));
        if (!pPacked) return E_OUTOFMEMORY;

        // Second call: actually pack
        if (!CredPackAuthenticationBufferW(
                0,
                const_cast<LPWSTR>(qualifiedUsername.c_str()),
                const_cast<LPWSTR>(password.c_str()),
                pPacked, &cbPacked)) {
            CoTaskMemFree(pPacked);
            return HRESULT_FROM_WIN32(GetLastError());
        }

        // Look up the MSV1_0 (NTLM) authentication package — works for local accounts
        ULONG ulAuthPackage = 0;
        HANDLE hLsa = NULL;
        LSA_STRING lsaName;
        lsaName.Buffer        = const_cast<char*>("NTLM");
        lsaName.Length        = 4;
        lsaName.MaximumLength = 4;
        if (LsaConnectUntrusted(&hLsa) == 0) {
            LsaLookupAuthenticationPackage(hLsa, &lsaName, &ulAuthPackage);
            LsaDeregisterLogonProcess(hLsa);
        }

        pcpcs->clsidCredentialProvider = CLSID_KeyLinkProvider;
        pcpcs->rgbSerialization        = pPacked;
        pcpcs->cbSerialization         = cbPacked;
        pcpcs->ulAuthenticationPackage = ulAuthPackage;

        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

        if (ppszOptionalStatusText)
            CopyCoTaskMemString(L"Phone verified \u2014 unlocking...", ppszOptionalStatusText);
        if (pcpsiOptionalStatusIcon)
            *pcpsiOptionalStatusIcon = CPSI_SUCCESS;

        return S_OK;
    }

    if (_authSuccess.load()) {
        // Auth succeeded but no Windows credentials stored — stay on screen
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        pcpcs->clsidCredentialProvider = GUID_NULL;
        pcpcs->cbSerialization  = 0;
        pcpcs->rgbSerialization = NULL;
        if (ppszOptionalStatusText)
            CopyCoTaskMemString(L"Phone verified \u2014 unlocking...", ppszOptionalStatusText);
        if (pcpsiOptionalStatusIcon)
            *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
        return S_OK;
    }

    // Auth not yet complete — stay on screen and keep waiting
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    pcpcs->clsidCredentialProvider = GUID_NULL;
    pcpcs->cbSerialization  = 0;
    pcpcs->rgbSerialization = NULL;
    if (ppszOptionalStatusText)  *ppszOptionalStatusText  = NULL;
    if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_NONE;
    return S_OK;
}

// ─── Base64 decode (simple table-based, no external deps) ───────────────────
static std::vector<BYTE> Base64Decode(const std::string& in) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<BYTE> out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        auto pos = chars.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + (int)pos;
        valb += 6;
        if (valb >= 0) {
            out.push_back((BYTE)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ─── Build KERB_INTERACTIVE_UNLOCK_LOGON blob ────────────────────────────────
// Returns the serialized bytes to pass in CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION.
// Layout (all offsets relative to start of buffer):
//   KERB_INTERACTIVE_UNLOCK_LOGON header  (fixed-size)
//   wchar_t[] domain                      (UTF-16LE, no NUL)
//   wchar_t[] username                    (UTF-16LE, no NUL)
//   wchar_t[] password                    (UTF-16LE, no NUL)
static std::vector<BYTE> BuildKerbUnlockBlob(
    const std::wstring& domain,
    const std::wstring& username,
    const std::vector<BYTE>& pwUtf16LE)
{
    // KERB_INTERACTIVE_UNLOCK_LOGON starts with KERB_INTERACTIVE_LOGON
    // MessageType, LogonDomainName, UserName, Password (all UNICODE_STRING)
    // followed by a LogonId (LUID, zero for unlock)
    struct KIL {
        // Mimics KERB_INTERACTIVE_UNLOCK_LOGON layout
        ULONG  MessageType;       // KerbInteractiveLogon = 2
        UNICODE_STRING Domain;
        UNICODE_STRING Username;
        UNICODE_STRING Password;
        LUID   LogonId;           // zero
    };

    USHORT domLen  = (USHORT)(domain.size()  * sizeof(wchar_t));
    USHORT userLen = (USHORT)(username.size() * sizeof(wchar_t));
    USHORT passLen = (USHORT)pwUtf16LE.size();

    size_t headerSize = sizeof(KIL);
    size_t totalSize  = headerSize + domLen + userLen + passLen;

    std::vector<BYTE> buf(totalSize, 0);
    KIL* pKil = reinterpret_cast<KIL*>(buf.data());

    pKil->MessageType = 2;  // KerbInteractiveLogon
    pKil->LogonId     = {0, 0};

    // Pointers are RELATIVE to start of buffer (LogonUI will fix them up)
    BYTE* base = buf.data();
    BYTE* ptr  = base + headerSize;

    // Domain
    pKil->Domain.Length        = domLen;
    pKil->Domain.MaximumLength = domLen;
    pKil->Domain.Buffer        = reinterpret_cast<PWSTR>(ptr - base); // relative
    memcpy(ptr, domain.data(), domLen);
    ptr += domLen;

    // Username
    pKil->Username.Length        = userLen;
    pKil->Username.MaximumLength = userLen;
    pKil->Username.Buffer        = reinterpret_cast<PWSTR>(ptr - base);
    memcpy(ptr, username.data(), userLen);
    ptr += userLen;

    // Password
    pKil->Password.Length        = passLen;
    pKil->Password.MaximumLength = passLen;
    pKil->Password.Buffer        = reinterpret_cast<PWSTR>(ptr - base);
    memcpy(ptr, pwUtf16LE.data(), passLen);

    return buf;
}

IFACEMETHODIMP CCredentialProviderCredential::GetFieldState(
    DWORD dwFieldId, 
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, 
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) {
    
    if (!pcpfs || !pcpfis) return E_POINTER;

    switch (dwFieldId) {
        case FID_LOGO:
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            *pcpfis = CPFIS_NONE;
            break;
        case FID_TITLE:
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            *pcpfis = CPFIS_NONE;
            break;
        case FID_STATUS:
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            *pcpfis = CPFIS_NONE;
            break;
        default:
            *pcpfs = CPFS_HIDDEN;
            *pcpfis = CPFIS_NONE;
            break;
    }
    return S_OK;
}

IFACEMETHODIMP CCredentialProviderCredential::GetStringValue(DWORD dwFieldId, PWSTR* ppsz) {
    if (!ppsz) return E_POINTER;
    *ppsz = NULL;

    switch (dwFieldId) {
        case FID_TITLE:
            return CopyCoTaskMemString(L"KeyLink Verification", ppsz);
        case FID_STATUS:
            EnterCriticalSection(&_csStatus);
            HRESULT hr = CopyCoTaskMemString(_statusText, ppsz);
            LeaveCriticalSection(&_csStatus);
            return hr;
    }
    return E_INVALIDARG;
}

IFACEMETHODIMP CCredentialProviderCredential::GetBitmapValue(DWORD dwFieldId, HBITMAP* phbmp) {
    UNREFERENCED_PARAMETER(dwFieldId);
    if (!phbmp) return E_POINTER;
    *phbmp = NULL; // Return NULL to let LogonUI display a default system icon
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProviderCredential::GetCheckboxValue(DWORD dwFieldId, BOOL* pfChecked, PWSTR* ppszLabel) {
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(pfChecked);
    UNREFERENCED_PARAMETER(ppszLabel);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProviderCredential::GetSubmitButtonValue(DWORD dwFieldId, DWORD* pdwAdjacentTo) {
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(pdwAdjacentTo);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProviderCredential::SetStringValue(DWORD dwFieldId, PCWSTR psz) {
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(psz);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProviderCredential::SetCheckboxValue(DWORD dwFieldId, BOOL fChecked) {
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(fChecked);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProviderCredential::SetComboBoxSelectedValue(DWORD dwFieldId, DWORD dwSelectedIndex) {
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(dwSelectedIndex);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProviderCredential::CommandLinkClicked(DWORD dwFieldId) {
    UNREFERENCED_PARAMETER(dwFieldId);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProviderCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, PWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {
    UNREFERENCED_PARAMETER(ntsStatus);
    UNREFERENCED_PARAMETER(ntsSubstatus);
    UNREFERENCED_PARAMETER(ppszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    return S_OK;
}

IFACEMETHODIMP CCredentialProviderCredential::Advise(ICredentialProviderCredentialEvents* pEvents) {
    if (_pCredentialEvents) {
        _pCredentialEvents->Release();
    }
    _pCredentialEvents = pEvents;
    if (_pCredentialEvents) {
        _pCredentialEvents->AddRef();
    }
    return S_OK;
}

IFACEMETHODIMP CCredentialProviderCredential::UnAdvise() {
    if (_pCredentialEvents) {
        _pCredentialEvents->Release();
        _pCredentialEvents = NULL;
    }
    return S_OK;
}

IFACEMETHODIMP CCredentialProviderCredential::SetSelected(BOOL* pfAutoSubmit) {
    if (pfAutoSubmit) {
        // If BLE auth already succeeded before the tile was selected, auto-submit immediately
        *pfAutoSubmit = _authSuccess.load() ? TRUE : FALSE;
    }
    return S_OK;
}

IFACEMETHODIMP CCredentialProviderCredential::SetDeselected() {
    return S_OK;
}

IFACEMETHODIMP CCredentialProviderCredential::GetComboBoxValueCount(DWORD dwFieldId, DWORD* pcItems, DWORD* pdwSelectedItem) {
    UNREFERENCED_PARAMETER(dwFieldId);
    if (pcItems) *pcItems = 0;
    if (pdwSelectedItem) *pdwSelectedItem = 0;
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredentialProviderCredential::GetComboBoxValueAt(DWORD dwFieldId, DWORD dwIndex, PWSTR* ppszValue) {
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(dwIndex);
    if (ppszValue) *ppszValue = NULL;
    return E_NOTIMPL;
}

void CCredentialProviderCredential::UpdateStatus(const std::wstring& newStatus) {
    EnterCriticalSection(&_csStatus);
    _statusText = newStatus;
    LeaveCriticalSection(&_csStatus);

    // Call SetFieldString on _pCredentialEvents for in-place label updates
    // This avoids calling the provider's CredentialsChanged()
    if (_pCredentialEvents) {
        _pCredentialEvents->SetFieldString(this, FID_STATUS, newStatus.c_str());
    }
}

void CCredentialProviderCredential::TriggerAutoSubmit() {
    // Mark auth as succeeded so GetSerialization returns CPGSR_RETURN_CREDENTIAL_FINISHED
    _authSuccess.store(true);

    // Ask LogonUI to re-enumerate credentials. This causes it to call GetCredentialCount
    // and then SetSelected on our tile, which will see pfAutoSubmit=TRUE and call
    // GetSerialization — completing the unlock.
    if (_pProvider) {
        ICredentialProviderEvents* pEvents = _pProvider->GetEvents();
        if (pEvents) {
            pEvents->CredentialsChanged(_pProvider->GetAdviseContext());
        }
    }
}

// Background Named Pipe Client Thread
DWORD WINAPI CCredentialProviderCredential::PipeThreadProc(LPVOID lpParam) {
    CCredentialProviderCredential* pThis = static_cast<CCredentialProviderCredential*>(lpParam);
    if (pThis) {
        pThis->PipeClientLoop();
    }
    return 0;
}

void CCredentialProviderCredential::PipeClientLoop() {
    const wchar_t* pipeName = L"\\\\.\\pipe\\KeyLinkLogonPipe";
    
    while (!_stopThread) {
        // Attempt to connect to the local Named Pipe
        HANDLE hPipe = CreateFileW(
            pipeName,
            GENERIC_READ,
            0, NULL, OPEN_EXISTING,
            0, NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            // Server not listening yet, wait and retry
            Sleep(500);
            continue;
        }

        // Successfully connected! Update label to initial waiting state
        UpdateStatus(L"Waiting for phone...");

        std::string lineBuffer;

        while (!_stopThread) {
            // Read from the named pipe byte-by-byte (simplifies line parsing without blocking indefinitely)
            // Using PeekNamedPipe can let us check if there is data before reading, avoiding blocks on exit.
            DWORD bytesAvail = 0;
            if (PeekNamedPipe(hPipe, NULL, 0, NULL, &bytesAvail, NULL)) {
                if (bytesAvail > 0) {
                    char ch;
                    DWORD read = 0;
                    if (ReadFile(hPipe, &ch, 1, &read, NULL) && read > 0) {
                        if (ch == '\n') {
                            // Strip trailing carriage return if any
                            if (!lineBuffer.empty() && lineBuffer.back() == '\r') {
                                lineBuffer.pop_back();
                            }
                            
                            // Handle the exact states
                            if (lineBuffer.substr(0, 7) == "UNLOCK:") {
                                // Format: UNLOCK:<username>:<base64-password-utf16le>
                                std::string payload = lineBuffer.substr(7);
                                auto sep = payload.find(':');
                                if (sep != std::string::npos) {
                                    std::string userUtf8 = payload.substr(0, sep);
                                    std::string pwB64    = payload.substr(sep + 1);

                                    // Convert username to wstring
                                    int wlen = MultiByteToWideChar(CP_UTF8, 0,
                                        userUtf8.c_str(), -1, NULL, 0);
                                    _winUsername.resize(wlen > 0 ? wlen - 1 : 0);
                                    MultiByteToWideChar(CP_UTF8, 0,
                                        userUtf8.c_str(), -1,
                                        &_winUsername[0], wlen);

                                    // Decode base64 password (already UTF-16LE bytes)
                                    _winPasswordBlob = Base64Decode(pwB64);

                                    UpdateStatus(L"Phone verified! Unlocking PC...");
                                    TriggerAutoSubmit();
                                } else {
                                    // Malformed UNLOCK, fallback to success display
                                    UpdateStatus(L"Phone verified! Unlocking PC...");
                                    TriggerAutoSubmit();
                                }
                            } else if (lineBuffer == "AUTHENTICATION_PENDING") {
                                UpdateStatus(L"Authenticating on phone...");
                            } else if (lineBuffer == "AUTHENTICATION_SUCCESS") {
                                // Legacy fallback (no credentials stored)
                                UpdateStatus(L"Phone verified! Unlocking PC...");
                                TriggerAutoSubmit();
                            } else if (lineBuffer == "AUTHENTICATION_FAILED") {
                                UpdateStatus(L"Authentication Failed");
                                _authSuccess.store(false);
                                _winUsername.clear();
                                _winPasswordBlob.clear();
                            }
                            
                            lineBuffer.clear();
                        } else {
                            lineBuffer.push_back(ch);
                        }
                    } else {
                        // ReadFile failed (pipe might have closed)
                        break;
                    }
                } else {
                    // No data available yet, sleep a bit to avoid CPU pegging
                    Sleep(50);
                }
            } else {
                // PeekNamedPipe failed, check if connection is dead
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE || err == ERROR_INVALID_HANDLE || err == ERROR_PIPE_NOT_CONNECTED) {
                    break;
                }
                Sleep(50);
            }
        }

        // Connection broken, reset UI and close handle
        CloseHandle(hPipe);
        UpdateStatus(L"Waiting for phone...");
        Sleep(500);
    }
}
