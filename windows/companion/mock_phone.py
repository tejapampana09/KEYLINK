import sys
import socket
import json
import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding, 
    PublicFormat, 
    PrivateFormat, 
    NoEncryption, 
    load_pem_private_key
)

PORT = 21035
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock_private_key.pem")

def read_line(s):
    buffer = bytearray()
    while True:
        data = s.recv(1)
        if not data:
            return None
        if data == b'\n':
            return buffer.decode('utf-8')
        buffer.extend(data)

def send_json(s, data):
    payload = json.dumps(data) + "\n"
    s.sendall(payload.encode('utf-8'))

def get_or_generate_key(generate_new=False):
    """Loads private key from disk if it exists, otherwise generates it."""
    if not generate_new and os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return load_pem_private_key(f.read(), password=None)
    
    # Generate P-256 ECC private key
    private_key = ec.generate_private_key(ec.SECP256R1())
    # Save it to disk
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    with open(KEY_FILE, "wb") as f:
        f.write(pem)
    return private_key

def run_pairing():
    print("--- Starting Mock Phone Pairing ---")
    private_key = get_or_generate_key(generate_new=True)
    public_key = private_key.public_key()
    pubkey_der = public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    pubkey_hex = pubkey_der.hex()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"[Mock TCP] Connecting for pairing on localhost:{PORT}...")
        s.connect(("127.0.0.1", PORT))
        
        pair_req = {
            "action": "pair",
            "device_name": "Mock Test Phone",
            "public_key": pubkey_hex
        }
        print("[Mock TCP] Sending pairing request...")
        send_json(s, pair_req)
        
        raw_msg = read_line(s)
        if not raw_msg:
            print("[Mock Error] Connection closed by companion.")
            return
        
        msg = json.loads(raw_msg)
        if msg.get("action") != "challenge":
            print(f"[Mock Error] Unexpected response: {msg}")
            return
            
        challenge_hex = msg.get("challenge")
        print(f"[Mock TCP] Received trial challenge: {challenge_hex}")
        
        challenge_bytes = bytes.fromhex(challenge_hex)
        signature = private_key.sign(
            challenge_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        resp = {
            "action": "response",
            "signature": signature.hex()
        }
        print("[Mock TCP] Sending signature response...")
        send_json(s, resp)
        
        raw_result = read_line(s)
        if not raw_result:
            print("[Mock Error] Connection closed before result.")
            return
            
        result = json.loads(raw_result)
        print(f"[Mock Result] Status: {result.get('status')}, Message: {result.get('message')}")
        
    except Exception as e:
        print(f"[Mock Error] Pairing socket error: {e}")
    finally:
        s.close()

def run_authentication():
    print("--- Starting Mock Phone Authentication ---")
    if not os.path.exists(KEY_FILE):
        print("[Mock Error] No private key found! You must pair first.")
        return
        
    private_key = get_or_generate_key(generate_new=False)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"[Mock TCP] Connecting for authentication...")
        s.connect(("127.0.0.1", PORT))
        
        auth_req = {
            "action": "auth"
        }
        print("[Mock TCP] Sending auth request...")
        send_json(s, auth_req)
        
        raw_msg = read_line(s)
        if not raw_msg:
            print("[Mock Error] Connection closed by companion.")
            return
            
        msg = json.loads(raw_msg)
        if msg.get("action") != "challenge":
            print(f"[Mock Error] Unexpected response: {msg}")
            return
            
        challenge_hex = msg.get("challenge")
        print(f"[Mock TCP] Received auth challenge: {challenge_hex}")
        
        print("[Mock Sensor] Waiting for simulated fingerprint scan (1.5s)...")
        time.sleep(1.5)
        
        challenge_bytes = bytes.fromhex(challenge_hex)
        signature = private_key.sign(
            challenge_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        resp = {
            "action": "response",
            "signature": signature.hex()
        }
        print("[Mock TCP] Sending signature response...")
        send_json(s, resp)
        
        raw_result = read_line(s)
        if not raw_result:
            print("[Mock Error] Connection closed before result.")
            return
            
        result = json.loads(raw_result)
        print(f"[Mock Result] Status: {result.get('status')}, Message: {result.get('message')}")
        
    except Exception as e:
        print(f"[Mock Error] Authentication socket error: {e}")
    finally:
        s.close()

def main():
    if len(sys.argv) < 2:
        print("Usage: python mock_phone.py [pair|auth]")
        sys.exit(1)
        
    mode = sys.argv[1].lower()
    if mode == "pair":
        run_pairing()
    elif mode == "auth":
        run_authentication()
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)

if __name__ == "__main__":
    main()
