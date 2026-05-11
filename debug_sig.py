"""Debug signature parsing."""

import struct
from src.mingseal_immutable_memory.core.bsv_tx import (
    BSVTransaction, double_sha256, hash160
)

PRIVATE_KEY = "f9edfeebc7b10d098e37af4884daace0254039fb02dbc1172e8d1ce57d3641b2"
UTXO_TXID = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
UTXO_VOUT = 0
UTXO_SATOSHIS = 100000

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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

# Get subscript
pubkey_hash = hash160(pub_key_bytes)
subscript = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

# Sign
sig_with_hash_type = tx.sign_input(0, bytes.fromhex(PRIVATE_KEY), UTXO_SATOSHIS)

print(f"Signature with hash type (len={len(sig_with_hash_type)}):")
print(f"  hex: {sig_with_hash_type.hex()}")

# Parse DER signature
der_sig = sig_with_hash_type[:-1]  # Remove SIGHASH byte
sighash_byte = sig_with_hash_type[-1]

print(f"\nDER signature (len={len(der_sig)}):")
print(f"  hex: {der_sig.hex()}")
print(f"SIGHASH byte: 0x{sighash_byte:02x}")

# Manual DER parsing
print("\n=== DER Signature Analysis ===")
print(f"Byte 0: 0x{der_sig[0]:02x} (should be 0x30 - SEQUENCE)")
seq_len = der_sig[1]
print(f"Byte 1: 0x{der_sig[1]:02x} (sequence length = {seq_len})")

offset = 2
if der_sig[offset] == 0x02:
    print(f"Byte 2: 0x02 (INTEGER - R)")
    offset += 1
    r_len = der_sig[offset]
    print(f"Byte 3: 0x{der_sig[3]:02x} (R length = {r_len})")
    offset += 1
    r_bytes = der_sig[offset:offset+r_len]
    print(f"R bytes: {r_bytes.hex()}")
    r = int.from_bytes(r_bytes, 'big')
    print(f"R: {r}")
    offset += r_len

if offset < len(der_sig) and der_sig[offset] == 0x02:
    print(f"Byte {offset}: 0x02 (INTEGER - S)")
    offset += 1
    s_len = der_sig[offset]
    print(f"Byte {offset}: 0x{der_sig[offset]:02x} (S length = {s_len})")
    offset += 1
    s_bytes = der_sig[offset:offset+s_len]
    print(f"S bytes: {s_bytes.hex()}")
    s = int.from_bytes(s_bytes, 'big')
    print(f"S: {s}")
    offset += s_len

print(f"\nTotal DER bytes parsed: {offset}")
print(f"Expected total: {2 + der_sig[1]}")

# Check if signature is low-S
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N_OVER_2 = N // 2
print(f"\nN/2: {N_OVER_2}")
print(f"S: {s}")
print(f"S < N/2? {s < N_OVER_2}")
if s > N_OVER_2:
    print(f"WARNING: S > N/2! Should be normalized to {N - s}")

# Verify preimage and signature
print("\n=== BIP143 Verification ===")
preimage = tx._serialize_for_forkid(0, subscript, UTXO_SATOSHIS)
tx_hash = double_sha256(preimage)
print(f"Preimage hash (what we signed): {tx_hash.hex()}")

# Verify signature manually
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

public_key = private_key.public_key()
try:
    # Need to construct signature from r,s
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    r = int.from_bytes(der_sig[4:4+der_sig[3]], 'big')
    s_val = int.from_bytes(der_sig[4+der_sig[3]+2:4+der_sig[3]+2+der_sig[4+der_sig[3]+1]], 'big')
    print(f"\nDecoded R: {r}")
    print(f"Decoded S: {s_val}")
    
    # Re-encode and verify
    sig_der = encode_dss_signature(r, s_val)
    public_key.verify(sig_der, tx_hash, ec.ECDSA(hashes.SHA256()))
    print("Signature verification: PASSED")
except Exception as e:
    print(f"Signature verification: FAILED - {e}")

# Now let's also verify by checking what node would see
print("\n=== Full ScriptSig Analysis ===")
script_sig = bytes([len(sig_with_hash_type)]) + sig_with_hash_type + bytes([len(pub_key_bytes)]) + pub_key_bytes
print(f"ScriptSig length: {len(script_sig)}")
print(f"ScriptSig hex: {script_sig.hex()}")

# Split it manually
print(f"\n1-byte push: 0x{script_sig[0]:02x} (should be len of sig_with_hash_type = {len(sig_with_hash_type)})")
sig_part = script_sig[1:1+len(sig_with_hash_type)]
print(f"Signature part: {sig_part.hex()}")
print(f"  Last byte (sighash): 0x{sig_part[-1]:02x}")
pub_part = script_sig[1+len(sig_with_hash_type):]
print(f"\n1-byte push: 0x{pub_part[0]:02x} (should be 0x21 = 33 for compressed pubkey)")
pubkey_part = pub_part[1:]
print(f"Pubkey part: {pubkey_part.hex()}")
