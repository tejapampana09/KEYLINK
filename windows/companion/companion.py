import os
import sys
import json
import socket
import uuid
import secrets
import threading
import base64
import time
import hashlib
import hmac
import getpass
from pathlib import Path

# ── 1. Path Resolution & Base Directory Setup ──────────────────────────────
if getattr(sys, 'frozen', False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))

_LOGS_DIR = os.path.join(_APP_DIR, "logs")
os.makedirs(_LOGS_DIR, exist_ok=True)

STARTUP_LOG = os.path.join(_LOGS_DIR, "startup.log")
COMPANION_LOG = os.path.join(_LOGS_DIR, "companion.log")
CRASH_LOG = os.path.join(_LOGS_DIR, "crash.log")
HEALTH_JSON = os.path.join(_LOGS_DIR, "health.json")

class SafeStreamWrapper:
    def __init__(self, filepath):
        self.filepath = filepath
    def write(self, data):
        if not data:
            return
        try:
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(data)
        except Exception:
            pass
    def flush(self):
        pass

if sys.executable.endswith("pythonw.exe") or getattr(sys, 'frozen', False):
    sys.stdout = SafeStreamWrapper(COMPANION_LOG)
    sys.stderr = SafeStreamWrapper(COMPANION_LOG)

def log_startup(stage, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{stage}] {message}\n"
    try:
        with open(STARTUP_LOG, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass
    print(entry.strip())

def log_companion(level, module, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{level}] [{module}] {message}\n"
    try:
        with open(COMPANION_LOG, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass
    print(entry.strip())

def log_crash(module, error_msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [CRASH] [{module}] {error_msg}\n"
    try:
        with open(CRASH_LOG, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass
    print(entry.strip())

def update_health(state, gatt_status, rfcomm_status, pipe_status, error_msg=None):
    health_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pid": os.getpid(),
        "username": getpass.getuser(),
        "executable": sys.executable,
        "version": sys.version,
        "state": state,
        "gatt_status": gatt_status,
        "rfcomm_status": rfcomm_status,
        "pipe_status": pipe_status,
        "winrt_available": HAS_WINRT_BLE,
        "error": error_msg
    }
    try:
        with open(HEALTH_JSON, "w", encoding="utf-8") as f:
            json.dump(health_data, f, indent=2)
    except Exception:
        pass

# ── 2. Windows Named Mutex for Single Instance Protection ─────────────────
import win32event
import win32api
import winerror

def acquire_single_instance_mutex():
    mutex_name = "Global\\KeyLinkCompanion_SingleInstance_Mutex"
    try:
        h_mutex = win32event.CreateMutex(None, False, mutex_name)
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            log_startup("MUTEX_CHECK", "Another KeyLink Companion instance is already running. Exiting cleanly.")
            sys.exit(0)
        return h_mutex
    except Exception as e:
        log_startup("MUTEX_WARNING", f"Could not create global named mutex: {e}")
        return None

# ── 3. Imports & Dependencies ──────────────────────────────────────────────
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature

import win32pipe
import win32file
import pywintypes
import win32security
import win32con

import config

try:
    import asyncio
    from winrt.windows.devices.bluetooth import BluetoothAdapter
    from winrt.windows.devices.bluetooth.genericattributeprofile import (
        GattServiceProvider,
        GattLocalCharacteristicParameters,
        GattCharacteristicProperties,
        GattServiceProviderAdvertisingParameters,
        GattCommunicationStatus,
        GattProtectionLevel,
        GattServiceProviderAdvertisementStatus
    )
    from winrt.windows.storage.streams import DataReader, DataWriter
    HAS_WINRT_BLE = True
except ImportError as e:
    HAS_WINRT_BLE = False
    log_startup("IMPORT_WARNING", f"WinRT BLE dependencies missing: {e}")

SERVICE_UUID = uuid.UUID("d1a53e0f-1f03-4d90-a03f-8c96c5b3e480")
RX_CHAR_UUID = uuid.UUID("d1a53e0f-1f03-4d90-a03f-8c96c5b3e481")  # Phone -> Windows, Write
TX_CHAR_UUID = uuid.UUID("d1a53e0f-1f03-4d90-a03f-8c96c5b3e482")  # Windows -> Phone, Notify

async def check_ble_support_async():
    try:
        adapter = await BluetoothAdapter.get_default_async()
        if adapter is None:
            return False, "No Bluetooth adapter detected."
        if not adapter.is_peripheral_role_supported:
            return False, f"Bluetooth Adapter '{adapter.device_id}' does not support GATT peripheral role (advertising)."
        return True, f"Bluetooth Adapter '{adapter.device_id}' supports BLE peripheral advertising."
    except Exception as e:
        return False, f"Error checking Bluetooth adapter: {e}"

# ── 4. Named Pipe Server ───────────────────────────────────────────────────
class KeyLinkPipeServer:
    def __init__(self):
        self.pipe_name = r"\\.\pipe\KeyLinkLogonPipe"
        self.h_pipe = None
        self.lock = threading.Lock()
        self._client_connected = False
        self._stop = False
        self.buffered_state = None
        self.status = "INITIALIZING"

    def _make_sa(self):
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(True, None, False)
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        sa.bInheritHandle = False
        return sa

    def start(self):
        try:
            sa = self._make_sa()
            self.h_pipe = win32pipe.CreateNamedPipe(
                self.pipe_name,
                win32pipe.PIPE_ACCESS_OUTBOUND,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_NOWAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, sa
            )
            self.status = "WAITING_FOR_LOGONUI"
            log_companion("INFO", "PIPE", "Named Pipe created with permissive DACL successfully.")
            t = threading.Thread(target=self._reconnect_loop, daemon=True)
            t.start()
            return True
        except Exception as e:
            self.status = "FAILED"
            log_companion("ERROR", "PIPE", f"Failed to create Named Pipe: {e}")
            self.h_pipe = None
            return False

    def _reconnect_loop(self):
        while not self._stop:
            if not self.h_pipe:
                time.sleep(0.5)
                continue

            self._client_connected = False
            while not self._stop:
                try:
                    win32pipe.ConnectNamedPipe(self.h_pipe, None)
                    self._client_connected = True
                    self.status = "LOGONUI_CONNECTED"
                    log_companion("INFO", "PIPE", "Credential Provider DLL client connected!")
                    if self.buffered_state:
                        try:
                            log_companion("INFO", "PIPE", f"Flushing buffered state to LogonUI: {self.buffered_state}")
                            payload = (self.buffered_state + "\n").encode('utf-8')
                            win32file.WriteFile(self.h_pipe, payload)
                            if self.buffered_state.startswith("UNLOCK:"):
                                self.buffered_state = None
                        except Exception as e:
                            log_companion("ERROR", "PIPE", f"Failed to flush buffered state: {e}")
                    break
                except pywintypes.error as e:
                    if e.winerror == 535:  # Already connected
                        self._client_connected = True
                        self.status = "LOGONUI_CONNECTED"
                        if self.buffered_state:
                            try:
                                payload = (self.buffered_state + "\n").encode('utf-8')
                                win32file.WriteFile(self.h_pipe, payload)
                                if self.buffered_state.startswith("UNLOCK:"):
                                    self.buffered_state = None
                            except Exception as ex:
                                log_companion("ERROR", "PIPE", f"Failed to flush buffered state: {ex}")
                        break
                    elif e.winerror == 536:  # Pipe listening
                        time.sleep(0.1)
                        continue
                    else:
                        log_companion("ERROR", "PIPE", f"ConnectNamedPipe failed: {e}")
                        time.sleep(0.5)
                        break

            while not self._stop and self._client_connected:
                time.sleep(0.2)

            if not self._stop:
                try:
                    win32pipe.DisconnectNamedPipe(self.h_pipe)
                    self.status = "WAITING_FOR_LOGONUI"
                    log_companion("INFO", "PIPE", "LogonUI disconnected. Ready for next lock screen connection.")
                except Exception:
                    pass

    def send_state(self, state):
        with self.lock:
            self.buffered_state = state
            if not self.h_pipe:
                return
            if not self._client_connected:
                return
            try:
                payload = (state + "\n").encode('utf-8')
                win32file.WriteFile(self.h_pipe, payload)
                log_companion("INFO", "PIPE", f"Sent state to LogonUI: {state}")
                if state.startswith("UNLOCK:"):
                    self.buffered_state = None
            except pywintypes.error as e:
                log_companion("ERROR", "PIPE", f"Failed to write state '{state}': {e}")
                self._client_connected = False

    def close(self):
        self._stop = True
        if self.h_pipe:
            try:
                win32pipe.DisconnectNamedPipe(self.h_pipe)
                win32file.CloseHandle(self.h_pipe)
            except Exception:
                pass
            self.h_pipe = None

# ── 5. BLE GATT Server with Observable Advertising State ──────────────────
class KeyLinkBleServer:
    def __init__(self, pipe_server, pubkey_bytes):
        self.pipe_server = pipe_server
        self.pubkey_bytes = pubkey_bytes
        self.provider = None
        self.rx_char = None
        self.tx_char = None
        self.loop = None
        self.state = "DISCONNECTED"
        self.adv_status_str = "CREATED"
        self._write_token = None
        self._sub_token = None
        self._adv_token = None

        self.current_challenge_id = None
        self.current_challenge = None
        self.challenge_timestamp = 0
        self.auth_timer = None
        self.rx_buffer = ""
        self.MAX_MESSAGE_SIZE = 4096

    def log_state(self, new_state):
        if self.state != new_state:
            self.state = new_state
            log_companion("INFO", "BLE_STATE", f"GATT State -> {self.state}")

    def _on_adv_status_changed(self, sender, args):
        status_enum = args.error if hasattr(args, 'error') else sender.advertisement_status
        status_map = {
            0: "Created",
            1: "Started",
            2: "Stopped",
            3: "Aborted",
            4: "StartedWithoutAllAdvertisementData"
        }
        status_str = status_map.get(int(status_enum), f"Unknown({status_enum})")
        self.adv_status_str = status_str
        log_companion("INFO", "BLE_ADV", f"GATT Advertisement Status Changed -> {status_str}")

        if status_str in ("Stopped", "Aborted"):
            log_companion("WARNING", "BLE_ADV", "GATT advertisement stopped unexpectedly. Triggering restart...")
            if self.loop and self.provider:
                self.loop.call_soon_threadsafe(self._restart_advertising)

    def _restart_advertising(self):
        try:
            if self.provider:
                adv_params = GattServiceProviderAdvertisingParameters()
                adv_params.is_connectable = True
                adv_params.is_discoverable = True
                self.provider.start_advertising_with_parameters(adv_params)
                log_companion("INFO", "BLE_ADV", "Re-triggered GATT advertisement start.")
        except Exception as e:
            log_companion("ERROR", "BLE_ADV", f"Failed to restart GATT advertisement: {e}")

    async def start_async(self, loop):
        self.loop = loop
        self.log_state("INITIALIZING")

        # Retry loop for Bluetooth readiness with bounded exponential backoff
        backoff_delays = [2, 5, 10, 20, 30, 60]
        attempt = 0

        while True:
            supported, msg = await check_ble_support_async()
            if supported:
                log_companion("INFO", "BLE_INIT", f"Bluetooth readiness verified: {msg}")
                break

            delay = backoff_delays[min(attempt, len(backoff_delays) - 1)]
            log_companion("WARNING", "BLE_INIT", f"Bluetooth not ready yet: '{msg}'. Retrying in {delay}s...")
            update_health("WAITING_FOR_BLUETOOTH", "NOT_READY", "PENDING", "PENDING", error_msg=msg)
            await asyncio.sleep(delay)
            attempt += 1

        try:
            log_companion("INFO", "BLE_INIT", f"Creating GATT Service Provider (UUID: {SERVICE_UUID})...")
            result = await GattServiceProvider.create_async(SERVICE_UUID)
            if result.error != GattCommunicationStatus.SUCCESS:
                log_companion("ERROR", "BLE_INIT", f"Failed to create GATT service provider: {result.error}")
                return False

            self.provider = result.service_provider
            service = self.provider.service

            # Hook advertisement status changed listener
            self._adv_token = self.provider.add_advertisement_status_changed(self._on_adv_status_changed)

            # RX Characteristic (Write: Phone -> PC)
            rx_params = GattLocalCharacteristicParameters()
            rx_params.characteristic_properties = GattCharacteristicProperties.WRITE
            rx_params.write_protection_level = GattProtectionLevel.PLAIN

            rx_result = await service.create_characteristic_async(RX_CHAR_UUID, rx_params)
            if rx_result.error != GattCommunicationStatus.SUCCESS:
                log_companion("ERROR", "BLE_INIT", f"Failed to create RX characteristic: {rx_result.error}")
                return False
            self.rx_char = rx_result.characteristic

            # TX Characteristic (Notify: PC -> Phone)
            tx_params = GattLocalCharacteristicParameters()
            tx_params.characteristic_properties = (
                GattCharacteristicProperties.NOTIFY | GattCharacteristicProperties.READ
            )
            tx_params.read_protection_level = GattProtectionLevel.PLAIN

            tx_result = await service.create_characteristic_async(TX_CHAR_UUID, tx_params)
            if tx_result.error != GattCommunicationStatus.SUCCESS:
                log_companion("ERROR", "BLE_INIT", f"Failed to create TX characteristic: {tx_result.error}")
                return False
            self.tx_char = tx_result.characteristic

            self._write_token = self.rx_char.add_write_requested(self._on_write_requested)
            self._sub_token = self.tx_char.add_subscribed_clients_changed(self._on_subscription_changed)

            self.log_state("SCANNING")
            adv_params = GattServiceProviderAdvertisingParameters()
            adv_params.is_connectable = True
            adv_params.is_discoverable = True
            self.provider.start_advertising_with_parameters(adv_params)
            self.adv_status_str = "Started"
            log_companion("INFO", "BLE_INIT", "GATT Service Advertisement active and listening.")
            return True

        except Exception as e:
            log_companion("ERROR", "BLE_INIT", f"Exception starting BLE GATT server: {e}")
            return False

    def stop(self):
        try:
            if self.provider:
                self.provider.stop_advertising()
                if self._adv_token:
                    self.provider.remove_advertisement_status_changed(self._adv_token)
            if self.rx_char and self._write_token:
                self.rx_char.remove_write_requested(self._write_token)
            if self.tx_char and self._sub_token:
                self.tx_char.remove_subscribed_clients_changed(self._sub_token)
            self.log_state("DISCONNECTED")
        except Exception as e:
            log_companion("ERROR", "BLE_STOP", f"Exception stopping BLE: {e}")

    def _on_subscription_changed(self, sender, args):
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._handle_subscription_change(sender))
            )

    async def _handle_subscription_change(self, sender):
        try:
            clients_count = sender.subscribed_clients.size
            if clients_count > 0:
                self.log_state("CONNECTED")
            else:
                self.log_state("DISCONNECTED")
                if self.auth_timer:
                    self.auth_timer.cancel()
                    self.auth_timer = None
                self.current_challenge_id = None
                self.current_challenge = None
                self.challenge_timestamp = 0
                self.rx_buffer = ""
                self.log_state("SCANNING")
                self.pipe_server.send_state("Waiting for phone...")
        except Exception as e:
            log_companion("ERROR", "BLE_CALLBACK", f"Subscription change error: {e}")

    def _on_write_requested(self, sender, args):
        if self.loop:
            deferral = args.get_deferral()
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._handle_write_request(deferral, args))
            )

    async def _handle_write_request(self, deferral, args):
        try:
            request = await args.get_request_async()
            if request is None:
                deferral.complete()
                return

            reader = DataReader.from_buffer(request.value)
            chunk_str = reader.read_string(request.value.length)

            if hasattr(request, 'option') and request.option == 1:
                request.respond()
            deferral.complete()

            self.rx_buffer += chunk_str
            if len(self.rx_buffer) > self.MAX_MESSAGE_SIZE:
                log_companion("ERROR", "BLE_AUTH", "Buffer size exceeded limit. Clearing buffer.")
                self.rx_buffer = ""
                return

            if "\n" in self.rx_buffer:
                lines = self.rx_buffer.split("\n")
                self.rx_buffer = lines[-1]
                for line in lines[:-1]:
                    line = line.strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            await self._process_message(msg)
                        except Exception as e:
                            log_companion("ERROR", "BLE_AUTH", f"Invalid JSON received: {e}")
        except Exception as e:
            log_companion("ERROR", "BLE_AUTH", f"Error handling write request: {e}")
            try:
                deferral.complete()
            except Exception:
                pass

    async def start_authentication(self):
        self.log_state("AUTHENTICATING")
        self.pipe_server.send_state("AUTHENTICATION_PENDING")
        self.current_challenge_id = str(uuid.uuid4())
        self.current_challenge = secrets.token_bytes(32)
        self.challenge_timestamp = time.time()

        if self.auth_timer:
            self.auth_timer.cancel()
        self.auth_timer = self.loop.call_later(
            30.0, lambda: asyncio.create_task(self._handle_auth_timeout())
        )

        challenge_msg = {
            "type": "AUTH_CHALLENGE",
            "version": 1,
            "challenge_id": self.current_challenge_id,
            "challenge": base64.b64encode(self.current_challenge).decode('ascii')
        }
        await self._send_json(challenge_msg)

    async def _handle_auth_timeout(self):
        if self.state == "AUTHENTICATING":
            log_companion("WARNING", "BLE_AUTH", "Authentication timed out after 30s.")
            self.log_state("AUTH_FAILED")
            self.pipe_server.send_state("AUTHENTICATION_FAILED")
            await self._send_failure("TIMEOUT")
            self.log_state("SCANNING")

    async def _send_failure(self, reason):
        await self._send_json({
            "type": "AUTH_FAILURE",
            "version": 1,
            "reason": reason
        })

    async def _send_json(self, data):
        if not self.tx_char:
            return
        try:
            json_str = json.dumps(data) + "\n"
            msg_bytes = json_str.encode('utf-8')
            CHUNK_SIZE = 180
            for i in range(0, len(msg_bytes), CHUNK_SIZE):
                chunk = msg_bytes[i:i + CHUNK_SIZE]
                writer = DataWriter()
                writer.write_bytes(chunk)
                buffer = writer.detach_buffer()
                await self.tx_char.notify_value_async(buffer)
                await asyncio.sleep(0.05)
        except Exception as e:
            log_companion("ERROR", "BLE_AUTH", f"Failed to send GATT notification: {e}")

    async def _process_message(self, msg):
        msg_type = msg.get("type")
        version = msg.get("version", 1)

        if msg_type not in ("AUTH_RESPONSE", "AUTH_REQUEST") and self.state != "AUTHENTICATED":
            log_companion("ERROR", "BLE_AUTH", f"Protected command rejected. Client state: {self.state}")
            await self._send_failure("UNAUTHORIZED")
            return

        if msg_type == "AUTH_REQUEST":
            log_companion("INFO", "BLE_AUTH", "Received AUTH_REQUEST from phone. Starting handshake...")
            await self.start_authentication()
            return

        if msg_type == "AUTH_RESPONSE":
            if self.state != "AUTHENTICATING":
                log_companion("ERROR", "BLE_AUTH", "Received response but not in AUTHENTICATING state.")
                await self._send_failure("UNEXPECTED_STATE")
                return

            if self.auth_timer:
                self.auth_timer.cancel()
                self.auth_timer = None

            challenge_id = msg.get("challenge_id")
            response_b64 = msg.get("response")

            if version != 1:
                log_companion("ERROR", "BLE_AUTH", f"Unsupported protocol version: {version}")
                self.log_state("AUTH_FAILED")
                await self._send_failure("UNSUPPORTED_VERSION")
                return

            if not challenge_id or not response_b64:
                log_companion("ERROR", "BLE_AUTH", "Missing fields in response.")
                self.log_state("AUTH_FAILED")
                await self._send_failure("MISSING_FIELDS")
                return

            if challenge_id != self.current_challenge_id:
                log_companion("ERROR", "BLE_AUTH", "Challenge ID mismatch.")
                self.log_state("AUTH_FAILED")
                await self._send_failure("INVALID_CHALLENGE_ID")
                return

            if time.time() - self.challenge_timestamp > 30.0:
                log_companion("ERROR", "BLE_AUTH", "Challenge expired.")
                self.log_state("AUTH_FAILED")
                await self._send_failure("CHALLENGE_EXPIRED")
                return

            try:
                response_bytes = base64.b64decode(response_b64)
            except Exception as e:
                log_companion("ERROR", "BLE_AUTH", f"Invalid Base64 response: {e}")
                self.log_state("AUTH_FAILED")
                await self._send_failure("INVALID_BASE64")
                return

            # Strict Authentication Gate — Fail Closed
            is_valid = False
            try:
                trusted_info = config.load_trusted_device()
                if trusted_info and trusted_info[1]:
                    pub_key = load_der_public_key(trusted_info[1])
                    pub_key.verify(response_bytes, self.current_challenge, ec.ECDSA(hashes.SHA256()))
                    is_valid = True
                    log_companion("INFO", "BLE_AUTH", "ECDSA Signature verified successfully!")
            except Exception as e:
                log_companion("WARNING", "BLE_AUTH", f"ECDSA verification check: {e}")

            if not is_valid:
                try:
                    shared_secret = config.get_shared_secret()
                    expected_hmac = hmac.new(shared_secret, self.current_challenge, hashlib.sha256).digest()
                    if hmac.compare_digest(expected_hmac, response_bytes):
                        is_valid = True
                        log_companion("INFO", "BLE_AUTH", "HMAC verified successfully!")
                except Exception:
                    pass

            if is_valid:
                self.log_state("AUTHENTICATED")
                win_creds = config.load_windows_credentials()
                if win_creds:
                    win_user, win_pass = win_creds
                    pw_b64 = base64.b64encode(win_pass.encode('utf-16-le')).decode('ascii')
                    self.pipe_server.send_state(f"UNLOCK:{win_user}:{pw_b64}")
                    log_companion("INFO", "BLE_AUTH", f"Sent UNLOCK payload to LogonUI for user: {win_user}")
                else:
                    self.pipe_server.send_state("AUTHENTICATION_SUCCESS")

                await self._send_json({"type": "AUTH_SUCCESS", "version": 1, "message": "Authenticated!"})
            else:
                log_companion("ERROR", "BLE_AUTH", "Authentication signature/HMAC verification FAILED.")
                self.log_state("AUTH_FAILED")
                self.pipe_server.send_state("AUTHENTICATION_FAILED")
                await self._send_failure("INVALID_SIGNATURE")

# ── 6. RFCOMM Bluetooth Socket Server (Strict Authentication Fail-Closed) ───
def read_line(sock):
    buf = bytearray()
    while True:
        try:
            chunk = sock.recv(1)
            if not chunk:
                break
            if chunk == b'\n':
                break
            buf.extend(chunk)
        except Exception:
            break
    return buf.decode('utf-8', errors='ignore').strip()

def send_json(sock, data):
    payload = (json.dumps(data) + "\n").encode('utf-8')
    sock.sendall(payload)

def run_rfcomm_server(pipe_server, pubkey_bytes):
    try:
        rfcomm_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        bound_ch = 1
        for ch in [1, 4, 5]:
            try:
                rfcomm_sock.bind(('00:00:00:00:00:00', ch))
                bound_ch = ch
                break
            except Exception:
                continue
        rfcomm_sock.listen(1)
        log_companion("INFO", "RFCOMM", f"RFCOMM Socket Server listening on Channel {bound_ch}...")

        while True:
            try:
                conn, addr = rfcomm_sock.accept()
                log_companion("INFO", "RFCOMM", f"Connected by Bluetooth device: {addr}")

                raw_msg = read_line(conn)
                if not raw_msg:
                    conn.close()
                    continue

                try:
                    msg = json.loads(raw_msg)
                except Exception:
                    conn.close()
                    continue

                challenge = secrets.token_bytes(32)
                send_json(conn, {"action": "challenge", "challenge": challenge.hex()})

                raw_resp = read_line(conn)
                if not raw_resp:
                    conn.close()
                    continue

                try:
                    resp = json.loads(raw_resp)
                except Exception:
                    conn.close()
                    continue

                sig_hex = resp.get("signature", "")
                resp_b64 = resp.get("response", "")
                sig_bytes = bytes.fromhex(sig_hex) if sig_hex else (base64.b64decode(resp_b64) if resp_b64 else b"")

                # Strict Authentication Gate — Fail Closed
                is_valid = False
                try:
                    trusted_info = config.load_trusted_device()
                    if trusted_info and trusted_info[1] and sig_bytes:
                        pub_key = load_der_public_key(trusted_info[1])
                        pub_key.verify(sig_bytes, challenge, ec.ECDSA(hashes.SHA256()))
                        is_valid = True
                        log_companion("INFO", "RFCOMM", "ECDSA Signature verified over RFCOMM socket!")
                except Exception as e:
                    log_companion("WARNING", "RFCOMM", f"ECDSA verification check: {e}")

                if not is_valid and sig_bytes:
                    try:
                        shared_secret = config.get_shared_secret()
                        expected_hmac = hmac.new(shared_secret, challenge, hashlib.sha256).digest()
                        if hmac.compare_digest(expected_hmac, sig_bytes):
                            is_valid = True
                            log_companion("INFO", "RFCOMM", "HMAC verified over RFCOMM socket!")
                    except Exception:
                        pass

                if is_valid:
                    win_creds = config.load_windows_credentials()
                    if win_creds:
                        win_user, win_pass = win_creds
                        pw_b64 = base64.b64encode(win_pass.encode('utf-16-le')).decode('ascii')
                        pipe_server.send_state(f"UNLOCK:{win_user}:{pw_b64}")
                        log_companion("INFO", "RFCOMM", f"Sent UNLOCK for user: {win_user}")
                    else:
                        pipe_server.send_state("AUTHENTICATION_SUCCESS")

                    send_json(conn, {"action": "result", "status": "success", "message": "Authentication successful!"})
                else:
                    log_companion("ERROR", "RFCOMM", "Authentication failed — invalid signature/HMAC. Rejecting connection.")
                    pipe_server.send_state("AUTHENTICATION_FAILED")
                    send_json(conn, {"action": "result", "status": "failed", "message": "Signature verification failed"})

                conn.close()
            except Exception as e:
                log_companion("ERROR", "RFCOMM", f"Socket connection error: {e}")
    except Exception as e:
        log_companion("ERROR", "RFCOMM", f"Could not start RFCOMM socket server: {e}")

# ── 7. Main Execution & Supervisor Loop ───────────────────────────────────
def run_authentication_mode():
    log_startup("STARTUP", "Initializing KeyLink Companion service...")

    # Single instance check
    h_mutex = acquire_single_instance_mutex()

    device_info = config.load_trusted_device()
    if device_info:
        device_name, pubkey_bytes = device_info
    else:
        device_name = "Unpaired Device"
        pubkey_bytes = b""
        log_startup("CONFIG_INFO", "No trusted device paired yet. Ready for GATT pairing...")

    log_startup("CONFIG_INFO", f"Paired Device Target: {device_name}")

    # 1. Named Pipe Server
    pipe_server = KeyLinkPipeServer()
    if not pipe_server.start():
        log_startup("PIPE_ERROR", "Failed to start Named Pipe server.")

    # 2. RFCOMM Thread
    rfcomm_thread = threading.Thread(
        target=run_rfcomm_server, args=(pipe_server, pubkey_bytes), daemon=True
    )
    rfcomm_thread.start()

    # 3. BLE GATT Server Thread
    ble_thread = None
    ble_context = {}
    if HAS_WINRT_BLE:
        def run_ble():
            nonlocal ble_context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ble_context["loop"] = loop

            ble_server = KeyLinkBleServer(pipe_server, pubkey_bytes)
            ble_context["server"] = ble_server

            success = loop.run_until_complete(ble_server.start_async(loop))
            if not success:
                log_crash("BLE", "GATT peripheral start_async returned False.")
                loop.close()
                return

            try:
                loop.run_forever()
            except KeyboardInterrupt:
                pass
            finally:
                ble_server.stop()
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
                log_companion("INFO", "BLE", "GATT service loop shutdown complete.")

        ble_thread = threading.Thread(target=run_ble, daemon=True)
        ble_thread.start()
    else:
        log_startup("BLE_WARNING", "WinRT BLE is not available on this Python runtime environment.")

    log_startup("READY", "KeyLink Companion is operational. Entering Supervisor Loop...")
    update_health("READY", "Active", "Active", pipe_server.status)

    # Supervisor loop
    try:
        while True:
            time.sleep(2.0)
            gatt_status = "Active" if (ble_context.get("server") and ble_context["server"].adv_status_str == "Started") else "Pending/Stopped"
            rfcomm_status = "Active" if rfcomm_thread.is_alive() else "Dead"
            pipe_status = pipe_server.status

            update_health("RUNNING", gatt_status, rfcomm_status, pipe_status)

            if not rfcomm_thread.is_alive():
                log_crash("SUPERVISOR", "RFCOMM thread died. Restarting RFCOMM thread...")
                rfcomm_thread = threading.Thread(
                    target=run_rfcomm_server, args=(pipe_server, pubkey_bytes), daemon=True
                )
                rfcomm_thread.start()

    except KeyboardInterrupt:
        log_startup("SHUTDOWN", "Stopping KeyLink Companion.")
    finally:
        pipe_server.close()
        if HAS_WINRT_BLE and ble_thread and "loop" in ble_context:
            loop_ref = ble_context["loop"]
            loop_ref.call_soon_threadsafe(loop_ref.stop)
            ble_thread.join(timeout=2.0)
        log_startup("SHUTDOWN", "KeyLink Companion service stopped.")

def main():
    if "--autostart" in sys.argv or "-a" in sys.argv:
        run_authentication_mode()
        return

    while True:
        print("\n==================================================")
        print("            [Key] KEYLINK COMPANION MVP           ")
        print("==================================================")

        device_info = config.load_trusted_device()
        if device_info:
            print(f"Paired Device: {device_info[0]}")
        else:
            print("Paired Device: None (Unpaired)")

        print("\nMenu:")
        print("  1. Pair phone (over Wi-Fi)")
        print("  2. Wait for authentication (Challenge-Response Server)")
        print("  3. Clear paired phone")
        print("  4. Exit")

        choice = input("\nSelect an option [1-4]: ").strip()

        if choice == "1":
            print("Run autostart mode to pair via BLE GATT/RFCOMM.")
        elif choice == "2":
            run_authentication_mode()
        elif choice == "3":
            config.clear_trusted_device()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
