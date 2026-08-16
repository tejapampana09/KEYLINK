import sys
import os
import json
import ctypes
import ctypes.wintypes
import base64
import getpass
import socket

# When running as PyInstaller EXE, __file__ points to the temp extraction dir.
# Use sys.executable's directory so config persists next to the EXE.
if getattr(sys, 'frozen', False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(_APP_DIR, "trusted_device.json")

# ── DPAPI helpers ────────────────────────────────────────────────────────────

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]

def _dpapi_encrypt(plaintext: bytes) -> bytes:
    """Encrypt bytes with DPAPI (current user scope)."""
    crypt32 = ctypes.windll.crypt32
    inp = DATA_BLOB(len(plaintext), ctypes.cast(ctypes.create_string_buffer(plaintext), ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    result = ctypes.string_at(out.pbData, out.cbData)
    ctypes.windll.kernel32.LocalFree(out.pbData)
    return result

def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    """Decrypt DPAPI-protected bytes (current user scope)."""
    crypt32 = ctypes.windll.crypt32
    inp = DATA_BLOB(len(ciphertext), ctypes.cast(ctypes.create_string_buffer(ciphertext), ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    result = ctypes.string_at(out.pbData, out.cbData)
    ctypes.windll.kernel32.LocalFree(out.pbData)
    return result

# ── Trusted device helpers ───────────────────────────────────────────────────

def save_trusted_device(device_name, public_key_hex):
    """Saves the paired device's public key (hex) to a JSON file."""
    # Preserve existing password if already stored
    existing = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                existing = json.load(f)
        except Exception:
            pass

    config = {
        "device_name": device_name,
        "public_key": public_key_hex,
    }
    # Keep encrypted password across re-pairs
    if "windows_password_enc" in existing:
        config["windows_password_enc"] = existing["windows_password_enc"]
    if "windows_username" in existing:
        config["windows_username"] = existing["windows_username"]

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    print(f"[Config] Trusted device saved to {CONFIG_FILE}")

def load_trusted_device():
    """Loads the paired device config. Returns (device_name, public_key_bytes) or None."""
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        device_name = config.get("device_name", "Unknown Phone")
        public_key_hex = config.get("public_key")
        if not public_key_hex:
            return None
        public_key_bytes = bytes.fromhex(public_key_hex)
        return device_name, public_key_bytes
    except Exception as e:
        print(f"[Config] Error loading trusted device: {e}")
        return None

def clear_trusted_device():
    """Clears the stored trusted device details."""
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print("[Config] Cleared trusted device.")

def get_shared_secret():
    """Gets the shared secret for BLE HMAC-SHA256 authentication."""
    secret = os.environ.get("KEYLINK_SHARED_SECRET")
    if secret:
        return secret.encode('utf-8')

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
            secret = data.get("shared_secret")
            if secret:
                return secret.encode('utf-8')
        except Exception:
            pass

    return "dev_shared_secret_key_12345".encode('utf-8')

# ── Windows unlock credential helpers ────────────────────────────────────────

def save_windows_password(username: str, password: str):
    """Encrypt the Windows password with DPAPI and store it in trusted_device.json."""
    enc_bytes = _dpapi_encrypt(password.encode('utf-16-le'))
    enc_b64 = base64.b64encode(enc_bytes).decode('ascii')

    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
        except Exception:
            pass

    config["windows_username"] = username
    config["windows_password_enc"] = enc_b64

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    print("[Config] Windows password saved (DPAPI-encrypted).")

def load_windows_credentials():
    """
    Returns (username, password_utf16le_bytes) for use by the credential provider,
    or None if not stored.
    """
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        username = config.get("windows_username")
        enc_b64  = config.get("windows_password_enc")
        if not username or not enc_b64:
            return None
        enc_bytes = base64.b64decode(enc_b64)
        pw_utf16  = _dpapi_decrypt(enc_bytes)      # raw UTF-16LE bytes
        pw_str    = pw_utf16.decode('utf-16-le')   # plain text (for pipe transport)
        return username, pw_str
    except Exception as e:
        print(f"[Config] Error loading Windows credentials: {e}")
        return None

def ensure_windows_credentials():
    """
    If no Windows credentials are stored, prompt the user to enter them once.
    Returns True if credentials are available, False otherwise.
    """
    creds = load_windows_credentials()
    if creds:
        print(f"[Config] Windows credentials loaded for user: {creds[0]}")
        return True

    print("\n[KeyLink Setup] Windows unlock credentials not configured.")
    print("These are stored DPAPI-encrypted on this PC only.\n")
    try:
        default_user = os.environ.get("USERNAME", socket.gethostname())
        username = input(f"  Windows username [{default_user}]: ").strip() or default_user
        password = getpass.getpass("  Windows password: ")
        if not password:
            print("[Config] No password entered — unlock will not work.")
            return False
        save_windows_password(username, password)
        return True
    except (EOFError, KeyboardInterrupt):
        print("\n[Config] Credential setup skipped.")
        return False
