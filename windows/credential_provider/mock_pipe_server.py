import win32pipe
import win32file
import pywintypes
import time

pipe_name = r"\\.\pipe\KeyLinkLogonPipe"

def run_mock_server():
    print("=== KEYLINK MOCK NAMED PIPE SERVER (TEST UTILITY) ===")
    print(f"Creating pipe: {pipe_name}")
    
    try:
        h_pipe = win32pipe.CreateNamedPipe(
            pipe_name,
            win32pipe.PIPE_ACCESS_OUTBOUND,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 0, None
        )
    except Exception as e:
        print(f"[Error] Failed to create Named Pipe: {e}")
        return

    print("Pipe created. Waiting for C++ Credential Provider DLL to connect...")
    print("(Run your C++ DLL test client/host now.)")
    
    try:
        win32pipe.ConnectNamedPipe(h_pipe, None)
        print("[Success] C++ DLL client connected!")
    except pywintypes.error as e:
        if e.winerror == 535: # already connected
            print("[Success] Client already connected.")
        else:
            print(f"[Error] Connection failed: {e}")
            win32file.CloseHandle(h_pipe)
            return

    try:
        while True:
            print("\nSelect state to send:")
            print("  1. Send AUTHENTICATION_PENDING  (Status: Authenticating...)")
            print("  2. Send AUTHENTICATION_SUCCESS  (Status: Successful!)")
            print("  3. Send AUTHENTICATION_FAILED   (Status: Failed)")
            print("  4. Exit")
            
            choice = input("\nChoice [1-4]: ").strip()
            
            if choice == "1":
                state = "AUTHENTICATION_PENDING"
            elif choice == "2":
                state = "AUTHENTICATION_SUCCESS"
            elif choice == "3":
                state = "AUTHENTICATION_FAILED"
            elif choice == "4":
                print("Closing pipe and exiting.")
                break
            else:
                print("Invalid choice.")
                continue
                
            payload = (state + "\n").encode('utf-8')
            try:
                win32file.WriteFile(h_pipe, payload)
                print(f"[Sent] Pushed: {state}")
            except Exception as e:
                print(f"[Error] Failed to write to pipe: {e}")
                break
                
    finally:
        try:
            win32pipe.DisconnectNamedPipe(h_pipe)
            win32file.CloseHandle(h_pipe)
        except Exception:
            pass
        print("Pipe closed.")

if __name__ == "__main__":
    run_mock_server()
