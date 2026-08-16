#pragma once
#include <windows.h>
#include <credentialprovider.h>

class CCredentialProviderCredential; // Forward declaration

class CCredentialProvider : public ICredentialProvider {
public:
    // IUnknown methods
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // ICredentialProvider methods
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pfAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);
    
    // Pure virtual methods we need to implement
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pEvents, ULONG_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise(); // Note the capital 'A' to match Windows SDK interface

    CCredentialProvider();
    
    // Accessors for event callbacks (called by the credential tile thread)
    ICredentialProviderEvents* GetEvents() const { return _pEvents; }
    ULONG_PTR GetAdviseContext() const { return _upAdviseContext; }

protected:
    virtual ~CCredentialProvider();

private:
    long _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _usageScenario;
    CCredentialProviderCredential* _pCredential; // Our UI tile instance
    ICredentialProviderEvents* _pEvents;       // LogonUI event callback pointer
    ULONG_PTR _upAdviseContext;                 // LogonUI advice context
};
