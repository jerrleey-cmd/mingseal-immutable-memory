"""Test transaction broadcast on BSV network."""

import requests
from src.mingseal_immutable_memory.core.bsv_tx import (
    BSVTransaction, double_sha256, hash160
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Use the same test data
PRIVATE_KEY = "f9edfeebc7b10d098e37af4884daace0254039fb02dbc1172e8d1ce57d3641b2"
UTXO_TXID = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
UTXO_VOUT = 0
UTXO_SATOSHIS = 100000

# Derive keys
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

# Build transaction
tx = BSVTransaction()
tx.add_input(UTXO_TXID, UTXO_VOUT, UTXO_SATOSHIS)
tx.add_op_return_output(b"test data for BSV OP_RETURN")
tx.add_p2pkh_output(address_hash, UTXO_SATOSHIS - 1000)

# Sign
sig = tx.sign_input(0, bytes.fromhex(PRIVATE_KEY), UTXO_SATOSHIS)
print(f"Signature (len={len(sig)}): {sig.hex()}")
print(f"Last byte (sighash): 0x{sig[-1]:02x}")

# Build scriptSig
script_sig = bytes([len(sig)]) + sig + bytes([len(pub_key_bytes)]) + pub_key_bytes
tx.inputs[0]['script_sig'] = script_sig

# Serialize
tx_hex = tx.to_hex()
print(f"\nTransaction ({len(tx_hex)//2} bytes): {tx_hex}")

# Calculate txid
txid = double_sha256(bytes.fromhex(tx_hex))[::-1].hex()
print(f"TXID: {txid}")

# Broadcast
print("\n=== Broadcasting to BSV ===")
url = "https://api.whatsonchain.com/v1/bsv/main/tx/raw"
resp = requests.post(url, json={"txhex": tx_hex}, timeout=30)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.text}")
