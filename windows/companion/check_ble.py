import asyncio
import sys
import os

def run_diagnostics():
    print("=== KEYLINK WINDOWS BLE CAPABILITY DIAGNOSTIC ===")
    
    # 1. Check WinRT library imports
    try:
        import winrt
        from winrt.windows.devices.bluetooth import BluetoothAdapter
        from winrt.windows.devices.bluetooth.genericattributeprofile import GattServiceProvider
        print("[Pass] WinRT runtime libraries are installed and loadable.")
    except ImportError as e:
        print("[FAIL] WinRT libraries are missing or corrupt.")
        print(f"Error: {e}")
        print("\nPossible solutions:")
        print("  pip install winrt-runtime winrt-Windows.Devices.Bluetooth winrt-Windows.Devices.Bluetooth.GenericAttributeProfile winrt-Windows.Storage.Streams")
        sys.exit(1)
        
    # 2. Query Bluetooth adapter capabilities
    async def check_async():
        try:
            adapter = await BluetoothAdapter.get_default_async()
            if adapter is None:
                print("[FAIL] No Bluetooth adapter detected on this system.")
                print("  -> Troubleshooting: Ensure Bluetooth is enabled in Windows Quick Settings.")
                return
                
            print(f"[Pass] Bluetooth adapter detected!")
            print(f"  -> System Device ID: {adapter.device_id}")
            print(f"  -> Peripheral/GATT Server Role (Advertising): {'SUPPORTED' if adapter.is_peripheral_role_supported else 'UNSUPPORTED'}")
            print(f"  -> Central/GATT Client Role (Scanning):     {'SUPPORTED' if adapter.is_central_role_supported else 'UNSUPPORTED'}")
            
            if adapter.is_peripheral_role_supported:
                print("\n[SUCCESS] Your Windows hardware fully supports KeyLink BLE Peripheral Mode!")
            else:
                print("\n[LIMITATION] Your Bluetooth adapter does not support BLE Peripheral advertising.")
                print("  -> Result: KeyLink will automatically run in Wi-Fi TCP mode as a fallback.")
        except Exception as ex:
            print(f"[ERROR] Exception checking Bluetooth adapter: {ex}")
            
    asyncio.run(check_async())

if __name__ == "__main__":
    run_diagnostics()
