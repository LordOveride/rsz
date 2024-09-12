import argparse
import hashlib
import requests

def hash160(pubkey):
    """Compute the HASH160 (RIPEMD160(SHA256(pubkey))) of a public key."""
    sha256 = hashlib.sha256(bytes.fromhex(pubkey)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    return ripemd160.hexdigest()

def fetch_raw_tx(txid):
    """Fetch the raw transaction hex from blockchain.info."""
    url = f"https://blockchain.info/rawtx/{txid}?format=hex"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception("Failed to fetch raw transaction")

def parse_tx(tx_hex):
    """Parse a raw Bitcoin transaction and extract the necessary data."""
    inputs = []
    try:
        cursor = 0
        # Skip version (4 bytes) and input count (1 byte)
        version = tx_hex[cursor:cursor+8]
        cursor += 8
        num_inputs = int(tx_hex[cursor:cursor+2], 16)
        cursor += 2

        print(f"Number of inputs: {num_inputs}")

        for _ in range(num_inputs):
            # Previous output (32 bytes) and index (4 bytes)
            prev_output = tx_hex[cursor:cursor+64]
            cursor += 64 + 8
            
            # Read script length
            script_len = int(tx_hex[cursor:cursor+2], 16) * 2
            cursor += 2
            
            # Read script
            script = tx_hex[cursor:cursor + script_len]
            cursor += script_len
            
            # Skip sequence (4 bytes)
            seq = tx_hex[cursor:cursor+8]
            cursor += 8
            
            inputs.append(script)
        
        # Skip output count (1 byte) and outputs (not needed here)
        output_count = int(tx_hex[cursor:cursor+2], 16)
        cursor += 2
        for _ in range(output_count):
            output_len = int(tx_hex[cursor:cursor+2], 16) * 2
            cursor += 2 + output_len
            cursor += 8  # Skip the script length and script

        # Skip locktime (4 bytes)
        locktime = tx_hex[cursor:cursor+8]
        
    except (IndexError, ValueError) as e:
        raise Exception(f"Error parsing transaction: {e}")

    return inputs

def compute_z_values(inputs):
    """Compute the Z values for the transaction inputs."""
    results = []
    for script in inputs:
        try:
            # Extract the r and s values
            if len(script) < 128:
                print(f"Warning: Script length is too short. Skipping: {script}")
                continue
            
            r = script[:64]
            s = script[64:128]
            # Compute Z value based on the whole script (or other data as needed)
            z = hashlib.sha256(hashlib.sha256(bytes.fromhex(script)).digest()).hexdigest()
            results.append((r, s, z, script))
        except Exception as e:
            print(f"Error computing Z values: {e}")
            continue
    return results

def main():
    parser = argparse.ArgumentParser(description="Compute RSZ values from a Bitcoin transaction ID.")
    parser.add_argument("-txid", required=True, help="Transaction ID to fetch and analyze.")
    args = parser.parse_args()
    
    try:
        raw_tx = fetch_raw_tx(args.txid)
        print(f"Raw Transaction: {raw_tx[:200]}...")  # Print first 200 chars for debug
        inputs = parse_tx(raw_tx)
        results = compute_z_values(inputs)
        
        for i, (r, s, z, script) in enumerate(results):
            print(f'Input #{i}:')
            print(f'  R: {r}')
            print(f'  S: {s}')
            print(f'  Z: {z}')
            print(f'  Script: {script}')
    
    except Exception as e:
        print(f'Error: {e}')

if __name__ == "__main__":
    main()
