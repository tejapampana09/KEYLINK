#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <string>
#include <atomic>
#include <vector>

class CCredentialProvider; // Forward declaration

class CCredentialProviderCredential : public ICredentialProviderCredential {
public:
    // IUnknown methods
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProviderCredential methods
    IFACEMETHODIMP GetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO* pcpus);
    IFACEMETHODIMP GetProviderGuid(GUID* pguidProvider);
    IFACEMETHODIMP GetUserSid(PWSTR* ppszUserSid);
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                    PWSTR* ppszOptionalStatusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP GetFieldState(DWORD dwFieldId, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldId, PWSTR* ppsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldId, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldId, BOOL* pfChecked, PWSTR* ppszLabel);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldId, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldId, PCWSTR psz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldId, BOOL fChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldId, DWORD dwSelectedIndex);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldId);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, PWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    
    // Remaining pure virtual methods
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pEvents);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pfAutoSubmit);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldId, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldId, DWORD dwIndex, PWSTR* ppszValue);

    CCredentialProviderCredential(CCredentialProvider* pProvider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus);

    // Initialization and Cleanup of the background pipe thread
    void Initialize();
    void Terminate();

    // Returns true if BLE authentication has succeeded
    bool IsAuthSucceeded() const { return _authSuccess.load(); }

private:
    virtual ~CCredentialProviderCredential();

    // Named Pipe client background thread
    static DWORD WINAPI PipeThreadProc(LPVOID lpParam);
    void PipeClientLoop();
    void UpdateStatus(const std::wstring& newStatus);
    void TriggerAutoSubmit();   // Called when AUTHENTICATION_SUCCESS received

    long _cRef;
    CCredentialProvider* _pProvider; // Reference to parent provider (owns pEvents callback)
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _usageScenario;

    std::wstring _statusText;        // Status string displayed on screen
    CRITICAL_SECTION _csStatus;      // Lock for status string updates
    
    HANDLE _hPipeThread;             // Background thread handle
    bool _stopThread;                // Thread termination flag
    std::atomic<bool> _authSuccess;  // Set true when AUTHENTICATION_SUCCESS received
    std::wstring _winUsername;        // Windows username from UNLOCK pipe message
    std::vector<BYTE> _winPasswordBlob; // UTF-16LE password bytes (from base64 decode)
    ICredentialProviderCredentialEvents* _pCredentialEvents; // In-place field updates event handler
};
