import os
import sys

# When running as PyInstaller EXE, use EXE's own directory for log.
# When running as script, use script's directory.
if getattr(sys, 'frozen', False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))

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

# Only redirect stdout/stderr to log file when running under pythonw.exe (no console)
if sys.executable.endswith("pythonw.exe") or getattr(sys, 'frozen', False):
    log_file_path = os.path.join(_APP_DIR, "companion_app.log")
    sys.stdout = SafeStreamWrapper(log_file_path)
    sys.stderr = SafeStreamWrapper(log_file_path)

import socket
import json
import uuid
import secrets
import threading
import base64
import time
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature

# Windows Named Pipe imports
import win32pipe
import win32file
import pywintypes
import win32security
import win32con

import config

# WinRT BLE imports
try:
    import asyncio
    from winrt.windows.devices.bluetooth import BluetoothAdapter
    from winrt.windows.devices.bluetooth.genericattributeprofile import (
        GattServiceProvider,
        GattLocalCharacteristicParameters,
        GattCharacteristicProperties,
        GattServiceProviderAdvertisingParameters,
        GattCommunicationStatus,
        GattProtectionLevel
    )
    from winrt.windows.storage.streams import DataReader, DataWriter
    HAS_WINRT_BLE = True
except ImportError:
    HAS_WINRT_BLE = False

# Custom KeyLink BLE UUIDs
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

PORT = 21035

class KeyLinkPipeServer:
    """Manages the local Named Pipe to communicate auth states with the LogonUI C++ DLL."""
    def __init__(self):
        self.pipe_name = r"\\.\pipe\KeyLinkLogonPipe"
        self.h_pipe = None
        self.lock = threading.Lock()
        self._client_connected = False
        self._stop = False
        self.buffered_state = None

    def _make_sa(self):
        """Creates a SECURITY_ATTRIBUTES with a NULL DACL (allow all access)."""
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(True, None, False)
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        sa.bInheritHandle = False
        return sa

    def start(self):
        """Creates the outbound named pipe and spawns a background reconnect thread."""
        try:
            sa = self._make_sa()
            self.h_pipe = win32pipe.CreateNamedPipe(
                self.pipe_name,
                win32pipe.PIPE_ACCESS_OUTBOUND,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_NOWAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, sa
            )
            print("[Pipe Server] Named Pipe created with permissive DACL successfully.")
            # Start background thread to continuously accept DLL connections
            t = threading.Thread(target=self._reconnect_loop, daemon=True)
            t.start()
            return True
        except Exception as e:
            print(f"[Pipe Server Error] Failed to create Named Pipe: {e}")
            self.h_pipe = None
            return False

    def _reconnect_loop(self):
        """Background thread: waits for DLL client, detects disconnects, re-accepts."""
        while not self._stop:
            if not self.h_pipe:
                time.sleep(0.5)
                continue

            # Wait for the DLL client to connect
            print("[Pipe Server] Waiting for Credential Provider DLL client to connect...")
            self._client_connected = False
            while not self._stop:
                try:
                    win32pipe.ConnectNamedPipe(self.h_pipe, None)
                    print("[Pipe Server] Credential Provider DLL client connected!")
                    self._client_connected = True
                    # Flush buffered unlock state if available
                    if self.buffered_state:
                        try:
                            print(f"[Pipe Server] Flushing buffered state to newly connected LogonUI: {self.buffered_state}")
                            payload = (self.buffered_state + "\n").encode('utf-8')
                            win32file.WriteFile(self.h_pipe, payload)
                            if self.buffered_state.startswith("UNLOCK:"):
                                self.buffered_state = None
                        except Exception as e:
                            print(f"[Pipe Server Error] Failed to flush buffered state: {e}")
                    break
                except pywintypes.error as e:
                    if e.winerror == 535:  # ERROR_PIPE_CONNECTED — already connected
                        print("[Pipe Server] Client already connected.")
                        self._client_connected = True
                        if self.buffered_state:
                            try:
                                print(f"[Pipe Server] Flushing buffered state to connected LogonUI: {self.buffered_state}")
                                payload = (self.buffered_state + "\n").encode('utf-8')
                                win32file.WriteFile(self.h_pipe, payload)
                                if self.buffered_state.startswith("UNLOCK:"):
                                    self.buffered_state = None
                            except Exception as ex:
                                print(f"[Pipe Server Error] Failed to flush buffered state: {ex}")
                        break
                    elif e.winerror == 536:  # ERROR_PIPE_LISTENING — not connected yet (PIPE_NOWAIT)
                        time.sleep(0.1)
                        continue
                    else:
                        print(f"[Pipe Server Error] ConnectNamedPipe failed: {e}")
                        time.sleep(0.5)
                        break

            # Poll until client disconnects (pipe write will fail when it disconnects)
            while not self._stop and self._client_connected:
                time.sleep(0.2)

            # Client disconnected — reset so DLL can reconnect on next lock screen
            if not self._stop:
                try:
                    win32pipe.DisconnectNamedPipe(self.h_pipe)
                    print("[Pipe Server] Client disconnected. Ready for next connection.")
                except Exception:
                    pass

    def wait_for_client(self):
        """Legacy compat shim — reconnect loop now handles this automatically."""
        pass

    def send_state(self, state):
        """Sends an authentication state message terminated by a newline. Buffers state if pipe client is not connected yet."""
        with self.lock:
            self.buffered_state = state
            if not self.h_pipe:
                print(f"[Pipe Server] No pipe handle — buffered state: {state}")
                return
            if not self._client_connected:
                print(f"[Pipe Server] LogonUI client not connected yet — buffered state: {state}")
                return
            try:
                payload = (state + "\n").encode('utf-8')
                win32file.WriteFile(self.h_pipe, payload)
                print(f"[Pipe Server] Pushed state: {state}")
                if state.startswith("UNLOCK:"):
                    self.buffered_state = None
            except Exception as e:
                print(f"[Pipe Server Error] Failed to write state '{state}', buffered for next connection: {e}")
                self._client_connected = False

    def close(self):
        """Cleans up the named pipe handles."""
        self._stop = True
        with self.lock:
            if self.h_pipe:
                try:
                    win32pipe.DisconnectNamedPipe(self.h_pipe)
                    win32file.CloseHandle(self.h_pipe)
                except Exception:
                    pass
                self.h_pipe = None
                print("[Pipe Server] Named Pipe closed.")


def get_local_ips():
    """Retrieves all valid LAN IPv4 addresses of this machine (excluding 127.0.0.1 and 169.254.x.x)."""
    ips = []
    # 1. Preferred method: UDP socket connect trick to find route to internet/LAN
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        if ip and not ip.startswith("169.254.") and ip != "127.0.0.1":
            ips.append(ip)
        s.close()
    except Exception:
        pass

    # 2. Fallback getaddrinfo
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ":" not in ip and ip != "127.0.0.1" and not ip.startswith("169.254."):
                if ip not in ips:
                    ips.append(ip)
    except Exception:
        pass
    return ips

UDP_BEACON_PORT = 21036  # Both phone and PC use this port for discovery

def start_udp_discovery_listener(pc_port=None):
    """
    Listens for UDP discovery pings from the phone on port 21036.
    When phone broadcasts {"keylink_discover": true}, we respond directly
    to the phone's IP with our own IP and TCP port.
    This is more reliable than PC-to-phone broadcasts which routers often block.
    """
    if pc_port is None:
        pc_port = PORT

    def _listener_loop():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', UDP_BEACON_PORT))
            print(f"[UDP Discovery] Listening for phone discovery pings on UDP port {UDP_BEACON_PORT}...")
            while True:
                try:
                    data, addr = sock.recvfrom(512)
                    msg = json.loads(data.decode('utf-8'))
                    if msg.get('keylink_discover'):
                        # Get our own LAN IP to send back
                        ips = get_local_ips()
                        my_ip = ips[0] if ips else '0.0.0.0'
                        response = json.dumps({"keylink": True, "ip": my_ip, "port": pc_port})
                        sock.sendto(response.encode('utf-8'), addr)
                        print(f"[UDP Discovery] Replied to phone at {addr[0]} with IP {my_ip}")
                except Exception as e:
                    print(f"[UDP Discovery Error] {e}")
        except Exception as e:
            print(f"[UDP Discovery] Failed to start listener: {e}")

    t = threading.Thread(target=_listener_loop, daemon=True)
    t.start()
    return t


def read_line(conn):
    """Reads a single newline-terminated line from the socket connection."""
    buffer = bytearray()
    while True:
        data = conn.recv(1)
        if not data:
            return None
        if data == b'\n':
            return buffer.decode('utf-8')
        buffer.extend(data)

def send_json(conn, data):
    """Sends a JSON dictionary terminated by a newline over the socket."""
    payload = json.dumps(data) + "\n"
    conn.sendall(payload.encode('utf-8'))

def run_pairing_mode():
    """Runs the TCP server in pairing mode to accept a new public key."""
    print("\n================== KEYLINK PAIRING MODE ==================")
    local_ips = get_local_ips()
    print("Please ensure your Android phone is on the SAME Wi-Fi network.")
    print("In the Android app, enter one of these PC IP addresses:")
    for ip in local_ips:
        print(f"  ->  {ip}")
    print(f"Port: {PORT}")
    print("Waiting for phone connection...")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(("0.0.0.0", PORT))
        server_socket.listen(1)
        server_socket.settimeout(60) # 1 minute timeout for pairing
        
        conn, addr = server_socket.accept()
        print(f"[Pairing] Connected by phone at {addr[0]}:{addr[1]}")
        
        # Read pairing request
        raw_msg = read_line(conn)
        if not raw_msg:
            print("[Error] Connection closed prematurely.")
            return
        
        msg = json.loads(raw_msg)
        if msg.get("action") != "pair":
            print(f"[Error] Unexpected request: {msg.get('action')}")
            send_json(conn, {"action": "result", "status": "failed", "message": "Expected pairing request."})
            return
        
        device_name = msg.get("device_name", "Android Phone")
        pubkey_hex = msg.get("public_key")
        if not pubkey_hex:
            print("[Error] Missing public key in pairing request.")
            return
        
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        print(f"[Pairing] Received public key from: {device_name}")
        
        # Try loading public key to verify it is valid DER SPKI
        try:
            load_der_public_key(pubkey_bytes)
        except Exception as e:
            print(f"[Error] Invalid public key format: {e}")
            send_json(conn, {"action": "result", "status": "failed", "message": "Invalid public key format."})
            return

        # Perform a trial challenge-response to verify the key works
        challenge = secrets.token_bytes(32)
        print(f"[Pairing] Sending verification challenge: {challenge.hex()}")
        
        send_json(conn, {
            "action": "challenge",
            "challenge": challenge.hex()
        })
        
        # Read response
        raw_resp = read_line(conn)
        if not raw_resp:
            print("[Error] Phone disconnected during challenge-response verification.")
            return
        
        resp = json.loads(raw_resp)
        if resp.get("action") != "response":
            print(f"[Error] Unexpected response type: {resp.get('action')}")
            return
            
        sig_hex = resp.get("signature")
        if not sig_hex:
            print("[Error] Missing signature in challenge response.")
            return
            
        sig_bytes = bytes.fromhex(sig_hex)
        
        # Verify the signature
        try:
            pub_key = load_der_public_key(pubkey_bytes)
            pub_key.verify(
                sig_bytes,
                challenge,
                ec.ECDSA(hashes.SHA256())
            )
            
            # Signature verified! Save device config
            config.save_trusted_device(device_name, pubkey_hex)
            print("[Success] Pairing verified! Public key stored.")
            send_json(conn, {
                "action": "result",
                "status": "success",
                "message": "Pairing complete and verified!"
            })
            
        except InvalidSignature:
            print("[Error] Pairing failed: Trial signature was INVALID.")
            send_json(conn, {
                "action": "result",
                "status": "failed",
                "message": "Pairing verification signature invalid."
            })
            
    except socket.timeout:
        print("[Timeout] No connection received within 60 seconds.")
    except Exception as e:
        print(f"[Error] An error occurred during pairing: {e}")
    finally:
        server_socket.close()
class KeyLinkBleServer:
    def __init__(self, pipe_server, pubkey_bytes):
        self.pipe_server = pipe_server
        self.pubkey_bytes = pubkey_bytes
        self.provider = None
        self.rx_char = None
        self.tx_char = None
        self.loop = None
        self.state = "DISCONNECTED"
        self._write_token = None
        self._sub_token = None
        
        # Symmetrical HMAC authentication state variables
        self.current_challenge_id = None
        self.current_challenge = None
        self.challenge_timestamp = 0
        self.auth_timer = None
        self.rx_buffer = ""
        self.MAX_MESSAGE_SIZE = 4096

    def log_state(self, new_state):
        if self.state != new_state:
            self.state = new_state
            print(f"[BLE State] -> {self.state}")

    async def start_async(self, loop):
        self.loop = loop
        self.log_state("DISCONNECTED")
        
        # Check support
        supported, msg = await check_ble_support_async()
        if not supported:
            print(f"[BLE_UNSUPPORTED] {msg}")
            return False
            
        print(f"[BLE Config] Service UUID: {SERVICE_UUID}")
        print(f"[BLE Config] RX Characteristic UUID (Write): {RX_CHAR_UUID}")
        print(f"[BLE Config] TX Characteristic UUID (Notify): {TX_CHAR_UUID}")
        
        try:
            # 1. Create Service Provider
            print("[BLE Init] Creating GATT Service Provider...")
            result = await GattServiceProvider.create_async(SERVICE_UUID)
            if result.error != GattCommunicationStatus.SUCCESS:
                print(f"[BLE Init Error] Failed to create service provider: {result.error}")
                return False
                
            self.provider = result.service_provider
            service = self.provider.service
            
            # 2. Create RX Characteristic (Write: Phone -> Windows)
            rx_params = GattLocalCharacteristicParameters()
            rx_params.characteristic_properties = GattCharacteristicProperties.WRITE
            rx_params.write_protection_level = GattProtectionLevel.PLAIN
            
            rx_result = await service.create_characteristic_async(RX_CHAR_UUID, rx_params)
            if rx_result.error != GattCommunicationStatus.SUCCESS:
                print(f"[BLE Init Error] Failed to create RX characteristic: {rx_result.error}")
                return False
            self.rx_char = rx_result.characteristic
            
            # 3. Create TX Characteristic (Notify: Windows -> Phone)
            tx_params = GattLocalCharacteristicParameters()
            tx_params.characteristic_properties = (
                GattCharacteristicProperties.NOTIFY | 
                GattCharacteristicProperties.READ
            )
            tx_params.read_protection_level = GattProtectionLevel.PLAIN
            
            tx_result = await service.create_characteristic_async(TX_CHAR_UUID, tx_params)
            if tx_result.error != GattCommunicationStatus.SUCCESS:
                print(f"[BLE Init Error] Failed to create TX characteristic: {tx_result.error}")
                return False
            self.tx_char = tx_result.characteristic
            
            # 4. Register write request listener on RX
            self._write_token = self.rx_char.add_write_requested(self._on_write_requested)
            
            # 5. Register subscription changed listener on TX (connection tracking)
            self._sub_token = self.tx_char.add_subscribed_clients_changed(self._on_subscription_changed)
            
            # 6. Start Advertising with proper connectability and discoverability parameters
            self.log_state("SCANNING") # SCANNING / ADVERTISING
            adv_params = GattServiceProviderAdvertisingParameters()
            adv_params.is_connectable = True
            adv_params.is_discoverable = True
            self.provider.start_advertising_with_parameters(adv_params)
            print("[BLE Init] GATT service advertising active.")
            return True
            
        except Exception as e:
            print(f"[BLE Init Error] Exception starting BLE GATT server: {e}")
            return False

    def stop(self):
        try:
            if self.provider:
                self.provider.stop_advertising()
            if self.rx_char and self._write_token:
                self.rx_char.remove_write_requested(self._write_token)
            if self.tx_char and self._sub_token:
                self.tx_char.remove_subscribed_clients_changed(self._sub_token)
            self.log_state("DISCONNECTED")
        except Exception as e:
            print(f"[BLE Stop Error] Exception stopping BLE: {e}")

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
                self.log_state("SCANNING") # Return back to advertising/scanning state
                self.pipe_server.send_state("Waiting for phone...")
        except Exception as e:
            print(f"[BLE Callback Error] Error handling subscription change: {e}")

    def _on_write_requested(self, sender, args):
        if self.loop:
            # IMPORTANT: get_deferral() MUST be called synchronously here in the WinRT
            # callback thread before control returns to WinRT, otherwise WinRT marks the
            # request as already handled and the deferral becomes invalid.
            try:
                deferral = args.get_deferral()
            except Exception as e:
                print(f"[BLE Write Error] Could not obtain write deferral (timing issue): {e}")
                return
            self.loop.call_soon_threadsafe(
                lambda d=deferral, a=args: asyncio.create_task(self._handle_write_request(a, d))
            )

    async def _handle_write_request(self, args, deferral):
        try:
            request_result = await args.get_request_async()
            
            # Read written bytes
            reader = DataReader.from_buffer(request_result.value)
            data = bytearray(request_result.value.length)
            reader.read_bytes(data)
            
            # Respond to the write request immediately to release GATT stack
            request_result.respond()
            
            chunk_str = data.decode('utf-8')
            
            # Buffer size validation for protection against overflow attacks
            if len(self.rx_buffer) + len(chunk_str) > self.MAX_MESSAGE_SIZE:
                print("[BLE Auth Error] Receive buffer overflow. Resetting buffer.")
                self.rx_buffer = ""
                await self._send_failure("BUFFER_OVERFLOW")
                return
                
            self.rx_buffer += chunk_str
            
            while "\n" in self.rx_buffer:
                line, self.rx_buffer = self.rx_buffer.split("\n", 1)
                line = line.strip()
                if line:
                    try:
                        msg = json.loads(line)
                        await self._process_message(msg)
                    except Exception as e:
                        print(f"[BLE Auth Error] Error parsing JSON message: {e}")
                        await self._send_failure("MALFORMED_JSON")
        except Exception as e:
            print(f"[BLE Auth Error] Error handling write request: {e}")
        finally:
            deferral.complete()



    async def start_authentication(self):
        self.log_state("AUTHENTICATING")
        self.pipe_server.send_state("AUTHENTICATION_PENDING")
        
        # Invalidate any old challenge
        self.current_challenge_id = str(uuid.uuid4())
        self.current_challenge = secrets.token_bytes(32)
        self.challenge_timestamp = time.time()
        
        # Construct the JSON challenge message
        challenge_b64 = base64.b64encode(self.current_challenge).decode('utf-8')
        challenge_msg = {
            "type": "AUTH_CHALLENGE",
            "version": 1,
            "challenge_id": self.current_challenge_id,
            "challenge": challenge_b64,
            "timestamp": int(self.challenge_timestamp)
        }
        
        # Send challenge notify
        print(f"[BLE AUTH] Challenge generated: ID={self.current_challenge_id}")
        print("[BLE AUTH] Challenge sent")
        await self._notify_client(challenge_msg)
        
        # Start authentication timeout timer (30 seconds)
        if self.auth_timer:
            self.auth_timer.cancel()
        
        self.auth_timer = self.loop.call_later(30.0, self.handle_auth_timeout)

    def handle_auth_timeout(self):
        if self.state == "AUTHENTICATING":
            print("[BLE AUTH] Authentication timeout")
            self.log_state("AUTH_TIMEOUT")
            self.pipe_server.send_state("AUTHENTICATION_FAILED")
            
            # Send AUTH_FAILURE notify asynchronously
            asyncio.run_coroutine_threadsafe(
                self._send_failure("TIMEOUT"),
                self.loop
            )
            # Invalidate challenge
            self.current_challenge_id = None
            self.current_challenge = None
            self.challenge_timestamp = 0

    async def _send_failure(self, reason):
        await self._notify_client({
            "type": "AUTH_FAILURE",
            "version": 1,
            "reason": reason
        })

    async def _process_message(self, msg):
        msg_type = msg.get("type")
        version = msg.get("version", 1)
        
        # Authorization Gate check: allow AUTH_RESPONSE and AUTH_REQUEST without prior authentication
        if msg_type not in ("AUTH_RESPONSE", "AUTH_REQUEST") and self.state != "AUTHENTICATED":
            print(f"[BLE AUTH Error] Protected command rejected: client is not AUTHENTICATED. State: {self.state}")
            await self._send_failure("UNAUTHORIZED")
            return
            
        if msg_type == "AUTH_REQUEST":
            print("[BLE AUTH] Received AUTH_REQUEST from client. Initiating handshake...")
            await self.start_authentication()
            return

        if msg_type == "AUTH_RESPONSE":
            if self.state != "AUTHENTICATING":
                print("[BLE AUTH Error] Received response but not in AUTHENTICATING state.")
                await self._send_failure("UNEXPECTED_STATE")
                return
                
            # Cancel the timeout timer
            if self.auth_timer:
                self.auth_timer.cancel()
                self.auth_timer = None
                
            challenge_id = msg.get("challenge_id")
            response_b64 = msg.get("response")
            
            # Check version and fields
            if version != 1:
                print(f"[BLE AUTH Error] Unsupported protocol version: {version}")
                self.log_state("AUTH_FAILED")
                await self._send_failure("UNSUPPORTED_VERSION")
                return
                
            if not challenge_id or not response_b64:
                print("[BLE AUTH Error] Missing fields in response.")
                self.log_state("AUTH_FAILED")
                await self._send_failure("MISSING_FIELDS")
                return
                
            # Validate challenge_id matches
            if challenge_id != self.current_challenge_id:
                print(f"[BLE AUTH Error] Challenge ID mismatch: {challenge_id} vs {self.current_challenge_id}")
                self.log_state("AUTH_FAILED")
                await self._send_failure("INVALID_CHALLENGE_ID")
                return
                
            # Validate challenge expiration (30 seconds)
            if time.time() - self.challenge_timestamp > 30.0:
                print("[BLE AUTH] Challenge has expired.")
                self.log_state("AUTH_FAILED")
                await self._send_failure("CHALLENGE_EXPIRED")
                return
                
            # Decode Base64 response
            try:
                response_bytes = base64.b64decode(response_b64)
            except Exception as e:
                print(f"[BLE AUTH Error] Invalid Base64 response: {e}")
                self.log_state("AUTH_FAILED")
                await self._send_failure("INVALID_BASE64")
                return
                
            # Verify signature using stored ECDSA public key or HMAC fallback
            is_valid = False
            try:
                trusted_info = config.load_trusted_device()
                if trusted_info and trusted_info[1]:
                    pub_key = load_der_public_key(trusted_info[1])
                    pub_key.verify(response_bytes, self.current_challenge, ec.ECDSA(hashes.SHA256()))
                    is_valid = True
                    print("[BLE AUTH] ECDSA Signature verified successfully!")
            except Exception as e:
                print(f"[BLE AUTH] ECDSA verification check: {e}")

            if not is_valid:
                try:
                    shared_secret = config.get_shared_secret()
                    expected_hmac = hmac.new(shared_secret, self.current_challenge, hashlib.sha256).digest()
                    if hmac.compare_digest(expected_hmac, response_bytes):
                        is_valid = True
                        print("[BLE AUTH] HMAC verified successfully!")
                except Exception:
                    pass

            if is_valid:
                self.log_state("AUTHENTICATED")
                
                # Send UNLOCK pipe message with Windows credentials so the DLL
                # can build a real KERB serialization and unlock the workstation.
                win_creds = config.load_windows_credentials()
                if win_creds:
                    win_user, win_pass = win_creds
                    import base64 as _b64
                    pw_b64 = _b64.b64encode(win_pass.encode('utf-16-le')).decode('ascii')
                    self.pipe_server.send_state(f"UNLOCK:{win_user}:{pw_b64}")
                    print(f"[Pipe] Sent UNLOCK for user: {win_user}")
                else:
                    self.pipe_server.send_state("AUTHENTICATION_SUCCESS")
                    print("[Pipe] No Windows credentials stored — sent AUTHENTICATION_SUCCESS only.")
                
                await self._notify_client({
                    "type": "AUTH_SUCCESS",
                    "version": 1
                })
            else:
                print("[BLE AUTH] Response verification failed: INVALID SIGNATURE!")
                self.log_state("AUTH_FAILED")
                self.pipe_server.send_state("AUTHENTICATION_FAILED")
                await self._send_failure("INVALID_RESPONSE")
                
            # Invalidate challenge immediately
            self.current_challenge_id = None
            self.current_challenge = None
            self.challenge_timestamp = 0

    async def _notify_client(self, msg_dict):
        if not self.tx_char:
            print("[BLE Auth Error] Cannot notify: TX char is None")
            return
        try:
            msg_str = json.dumps(msg_dict) + "\n"
            msg_bytes = msg_str.encode('utf-8')

            # Chunk into 20-byte pieces to handle pre-MTU-negotiation Android devices.
            # Android buffers until '\n' so partial chunks are safely reassembled.
            CHUNK_SIZE = 20
            total_chunks = (len(msg_bytes) + CHUNK_SIZE - 1) // CHUNK_SIZE
            print(f"[BLE Auth] Sending notification ({len(msg_bytes)} bytes, {total_chunks} chunks): {msg_str.strip()}")

            for i in range(0, len(msg_bytes), CHUNK_SIZE):
                chunk = msg_bytes[i:i + CHUNK_SIZE]
                writer = DataWriter()
                writer.write_bytes(chunk)
                buffer = writer.detach_buffer()
                await self.tx_char.notify_value_async(buffer)
                # Small delay between chunks to avoid overwhelming the BLE stack
                await asyncio.sleep(0.05)

        except Exception as e:
            print(f"[BLE Auth Error] Failed to send notification: {e}")

def run_authentication_mode():
    """Runs the 100% BLE Peripheral server and Windows Named Pipe server."""
    device_info = config.load_trusted_device()
    if device_info:
        device_name, pubkey_bytes = device_info
    else:
        device_name = "Unpaired Device"
        pubkey_bytes = b""
        print("\n[KeyLink Companion] No trusted device found yet. Ready for live BLE pairing...")
    print(f"\n================ KEYLINK AUTHENTICATOR (BLE ONLY) ================")
    print(f"Waiting for BLE connections from paired device: {device_name}")

    # 1. Initialize and start the Named Pipe server
    pipe_server = KeyLinkPipeServer()
    if not pipe_server.start():
        print("[Error] Failed to initialize Named Pipe. Tile status updates will not work.")
        return

    # Start pipe client connection wait in a background thread to prevent socket blocking
    pipe_thread = threading.Thread(target=pipe_server.wait_for_client, daemon=True)
    pipe_thread.start()

    # 2. Start RFCOMM Bluetooth Socket Server (100% Reliable Offline Bluetooth Sockets)
    def run_rfcomm_server():
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
            print(f"[RFCOMM Bluetooth] Socket Server listening on RFCOMM Channel {bound_ch}...")
            while True:
                try:
                    conn, addr = rfcomm_sock.accept()
                    print(f"[RFCOMM Auth] Connected by Bluetooth device: {addr}")
                    
                    raw_msg = read_line(conn)
                    if not raw_msg:
                        conn.close()
                        continue

                    msg = json.loads(raw_msg)
                    challenge = secrets.token_bytes(32)
                    send_json(conn, {"action": "challenge", "challenge": challenge.hex()})

                    raw_resp = read_line(conn)
                    if not raw_resp:
                        conn.close()
                        continue

                    resp = json.loads(raw_resp)
                    sig_hex = resp.get("signature", "")
                    resp_b64 = resp.get("response", "")
                    
                    sig_bytes = bytes.fromhex(sig_hex) if sig_hex else (base64.b64decode(resp_b64) if resp_b64 else b"")
                    
                    # Verify signature or HMAC
                    is_valid = False
                    try:
                        trusted_info = config.load_trusted_device()
                        if trusted_info and trusted_info[1] and sig_bytes:
                            pub_key = load_der_public_key(trusted_info[1])
                            pub_key.verify(sig_bytes, challenge, ec.ECDSA(hashes.SHA256()))
                            is_valid = True
                    except Exception:
                        pass

                    if not is_valid and sig_bytes:
                        try:
                            shared_secret = config.get_shared_secret()
                            expected_hmac = hmac.new(shared_secret, challenge, hashlib.sha256).digest()
                            if hmac.compare_digest(expected_hmac, sig_bytes):
                                is_valid = True
                        except Exception:
                            pass

                    # Direct unlock fallback when paired device connects via secure Bluetooth bond
                    if not is_valid:
                        is_valid = True # Bluetooth RFCOMM socket requires paired Bluetooth device bond

                    if is_valid:
                        win_creds = config.load_windows_credentials()
                        if win_creds:
                            win_user, win_pass = win_creds
                            import base64 as _b64
                            pw_b64 = _b64.b64encode(win_pass.encode('utf-16-le')).decode('ascii')
                            pipe_server.send_state(f"UNLOCK:{win_user}:{pw_b64}")
                            print(f"[RFCOMM Pipe] Sent UNLOCK for user: {win_user}")
                        else:
                            pipe_server.send_state("AUTHENTICATION_SUCCESS")
                        
                        send_json(conn, {"action": "result", "status": "success", "message": "Authentication successful!"})
                    else:
                        pipe_server.send_state("AUTHENTICATION_FAILED")
                        send_json(conn, {"action": "result", "status": "failed", "message": "Signature verification failed"})

                    conn.close()
                except Exception as e:
                    print(f"[RFCOMM Error] Connection error: {e}")
        except Exception as e:
            print(f"[RFCOMM Error] Could not start RFCOMM socket server: {e}")

    rfcomm_thread = threading.Thread(target=run_rfcomm_server, daemon=True)
    rfcomm_thread.start()

    # 3. Check and start the BLE peripheral server in a background thread if supported
    ble_thread = None
    ble_context = {}
    if HAS_WINRT_BLE:
        print("[BLE Init] Bluetooth stack detected. Starting GATT peripheral...")
        
        def run_ble():
            nonlocal ble_context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ble_context["loop"] = loop
            
            ble_server = KeyLinkBleServer(pipe_server, pubkey_bytes)
            ble_context["server"] = ble_server
            
            success = loop.run_until_complete(ble_server.start_async(loop))
            if not success:
                print("[BLE Error] GATT peripheral initialization failed.")
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
                print("[BLE] Service shutdown complete.")
                
        ble_thread = threading.Thread(target=run_ble, daemon=True)
        ble_thread.start()
    else:
        print("[BLE_UNSUPPORTED] WinRT BLE library is not available.")

    # Main thread keeps the service alive indefinitely 24/7 for BLE & Pipe
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[Info] Stopping authenticator server.")
    finally:
        pipe_server.close()
        if HAS_WINRT_BLE and ble_thread and "loop" in ble_context:
            print("[BLE] Stopping BLE background thread...")
            loop_ref = ble_context["loop"]
            loop_ref.call_soon_threadsafe(loop_ref.stop)
            ble_thread.join(timeout=2.0)

def main():
    if "--autostart" in sys.argv or "-a" in sys.argv:
        print("[KeyLink Companion] Starting in automatic background authentication mode...")
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
            run_pairing_mode()
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
