"""Get real BSV UTXO and test transaction."""

import requests
from src.mingseal_immutable_memory.core.bsv_tx import (
    BSVTransaction, double_sha256, hash160, build_and_sign_op_return_tx
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Use a known BSV address to get UTXOs
# This is a faucet address - just for testing
TEST_ADDRESS = "1HQTm7L2KXTmNTecedhFRnQqP98yU1GAD7"

# Get UTXOs for this address
url = f"https://api.whatsonchain.com/v1/bsv/main/address/{TEST_ADDRESS}/unspent"
print(f"Fetching UTXOs from: {url}")
resp = requests.get(url, timeout=30)
print(f"Status: {resp.status_code}")

if resp.status_code == 200:
    utxos = resp.json()
    print(f"Found {len(utxos)} UTXOs")
    if utxos:
        for i, utxo in enumerate(utxos[:3]):
            print(f"\nUTXO {i}:")
            print(f"  tx_hash: {utxo['tx_hash']}")
            print(f"  tx_pos: {utxo['tx_pos']}")
            print(f"  value: {utxo['value']} satoshis")
            print(f"  height: {utxo['height']}")
        
        # Use the first UTXO
        utxo = utxos[0]
        txid = utxo['tx_hash']
        vout = utxo['tx_pos']
        satoshis = utxo['value']
        
        print(f"\n=== Using UTXO ===")
        print(f"TXID: {txid}")
        print(f"VOUT: {vout}")
        print(f"SATOSHIS: {satoshis}")
        
        # The private key for 1HQTm7L2KXTmNTecedhFRnQqP98yU1GAD7
        # This is the test key from summary
        PRIVATE_KEY = "f9edfeebc7b10d098e37af4884daace0254039fb02dbc1172e8d1ce57d3641b2"
        
        # Verify address matches private key
        private_key = ec.derive_private_key(
            int.from_bytes(bytes.fromhex(PRIVATE_KEY), 'big'),
            ec.SECP256K1(),
            default_backend()
        )
        pub_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        address_hash = hash160(pub_key_bytes)
        
        from src.mingseal_immutable_memory.core.bsv_tx import base58_encode
        import hashlib
        
        # Create P2PKH address
        version = b'\x00'  # Mainnet P2PKH version
        payload = version + address_hash
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        addr = base58_encode(payload + checksum)
        print(f"\nDerived address: {addr}")
        print(f"Expected address: {TEST_ADDRESS}")
        print(f"Match: {addr == TEST_ADDRESS}")
        
        # Build and sign transaction
        OP_RETURN_DATA = b"MingSeal Test 2024"
        FEE = 1000
        CHANGE_AMOUNT = satoshis - FEE
        
        print(f"\nBuilding transaction...")
        print(f"  OP_RETURN data: {OP_RETURN_DATA}")
        print(f"  Change amount: {CHANGE_AMOUNT} satoshis")
        
        tx_hex = build_and_sign_op_return_tx(
            PRIVATE_KEY,
            txid,
            vout,
            satoshis,
            OP_RETURN_DATA,
            address_hash,
            fee=FEE
        )
        
        print(f"\nTransaction hex ({len(tx_hex)//2} bytes):")
        print(tx_hex)
        
        # Calculate txid
        txid_calc = double_sha256(bytes.fromhex(tx_hex))[::-1].hex()
        print(f"\nComputed TXID: {txid_calc}")
        
        # Broadcast
        print("\n=== Broadcasting to BSV ===")
        broadcast_url = "https://api.whatsonchain.com/v1/bsv/main/tx/raw"
        resp = requests.post(broadcast_url, json={"txhex": tx_hex}, timeout=30)
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.text}")
else:
    print(f"Error: {resp.text}")
