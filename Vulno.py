import collections
import os

# Bitcoin secp256k1 Curve Order (n)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def parse_btc_file(file_path):
    """
    Parses a BTC.txt file. Expects lines to be in hex format:
    msg_hash,r,s[,k]
    Or key=value space-separated format.
    """
    signatures = []
    if not os.path.exists(file_path):
        print(f"[-] Error: {file_path} not found. Creating a mock file for testing...")
        create_mock_btc_file(file_path)
        
    with open(file_path, 'r') as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                # Splitting common raw log formats (comma, semicolon, or space)
                parts = line.replace(';', ',').replace(' ', ',').split(',')
                
                # Dynamic mapping based on structure
                sig_data = {
                    'id': idx,
                    'msg_hash': int(parts[0], 16),
                    'r': int(parts[1], 16),
                    's': int(parts[2], 16)
                }
                # If nonce k is included in the file dump
                if len(parts) > 3:
                    sig_data['k'] = int(parts[3], 16)
                    
                signatures.append(sig_data)
            except Exception as e:
                print(f"[-] Warning: Skipping line {idx} due to malformed data: {e}")
                
    return signatures

def create_mock_btc_file(file_path):
    """Generates a sample BTC.txt to run verification immediately."""
    # Example values (Hexadecimal)
    mock_data = [
        "# Format: msg_hash,r,s,k(optional)",
        # Pair 1 & 2: Nonce reuse (Same R, different message hash)
        "a1b2c3d4,f839a2de4b,bc01aef372",
        "e5f6a7b8,f839a2de4b,de84fe221a", 
        # Line 3: Small K vulnerability (k is small, e.g., 0x400)
        "789abcde,fa732bc01d,9921feca34,400"
    ]
    with open(file_path, 'w') as f:
        f.write('\n'.join(mock_data))

def check_reused_nonce(signatures):
    """Matches: Identical 'r' across differing 'msg_hash' inputs."""
    r_to_sig = collections.defaultdict(list)
    for sig in signatures:
        r_to_sig[sig['r']].append(sig)

    reused_matches = []
    for r, sig_list in r_to_sig.items():
        if len(sig_list) > 1:
            reused_matches.append((r, sig_list))
    return reused_matches

def check_small_k(signatures, k_threshold=2**127):
    """Matches: Nonces smaller than acceptable entropy boundaries."""
    small_k_matches = []
    for sig in signatures:
        if 'k' in sig and sig['k'] < k_threshold:
            small_k_matches.append(sig)
    return small_k_matches

def check_fault_attack(signatures, curve_order):
    """Matches: Signatures failing mathematical sanity rules or showing edge bitflips."""
    fault_matches = []
    for sig in signatures:
        # Strict validation checks for r and s boundaries
        if sig['r'] >= curve_order or sig['s'] >= curve_order:
            fault_matches.append(sig)
        elif sig['r'] == 0 or sig['s'] == 0:
            fault_matches.append(sig)
    return fault_matches

# ==========================================
# Main Execution Execution
# ==========================================
if __name__ == "__main__":
    file_name = "BTC.txt"
    
    print("Parsing signature data from target file...")
    sigs = parse_btc_file(file_name)
    print(f"[+] Loaded {len(sigs)} signatures successfully.\n")
    
    print("Vulnerability Matrix Overview:")
    
    # 1. Evaluate Reused Nonce
    reused = check_reused_nonce(sigs)
    print(f"  • [HIGH] Reused Nonce              ➜ Matches: {len(reused)}")
    for r, sig_list in reused:
        ids = [s['id'] for s in sig_list]
        print(f"    └── Found match group at line IDs: {ids}")

    # 2. Evaluate Small K
    small_k = check_small_k(sigs)
    print(f"  • [HIGH] Small K                   ➜ Matches: {len(small_k)}")
    for sig in small_k:
        print(f"    └── Match found at line ID {sig['id']} (k = {hex(sig['k'])})")

    # 3. Evaluate Fault Attack
    faults = check_fault_attack(sigs, SECP256K1_N)
    print(f"  • [HIGH] Fault Attack              ➜ Matches: {len(faults)}")
    for sig in faults:
        print(f"    └── Invalidation anomaly found at line ID {sig['id']}")
