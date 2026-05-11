"""Verify the ECDSA signature in a BSV transaction against BIP143 preimage."""

import struct
from src.mingseal_immutable_memory.core.bsv_tx import double_sha256, hash160
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# The Python-generated transaction that was rejected
TX_HEX = "01000000019417ad02a47df611f75bd2b8f5acf3a5615211978e0872caaffb0d29ec97beb6010000006a473044022072fc2b0be0728314651fe3df6e4f1bf410f7ee7b39ea29034ca724855f1c79c002202c32712af7b30b369d952947b0419ec4d14e812956a96d6df6f87e52ae149a9c4121024483ccc23e3df5a9de9e1e33a9998ba79056b5a3353af91442b2805009a149a4ffffffff02000000000000000025006a224d696e675365616c2054657374205858585858585858585858585858585858585858282b0700000000001976a914b3f1eb0f62bf2e171bbba5638c7cc5e80345b8e188ac00000000"

UTXO_TXID = "b6be97ec290dfbafca72088e97115261a5f3acf5b8d25bf711f67da402ad1794"
UTXO_VOUT = 1
UTXO_SATOSHIS = 470800
PRIVATE_KEY = "f9edfeebc7b10d098e37af4884daace0254039fb02dbc1172e8d1ce57d3641b2"

raw = bytes.fromhex(TX_HEX)

# Parse transaction
off = 0
version = struct.unpack('<I', raw[off:off+4])[0]
off += 4
num_inputs = raw[off]; off += 1

# Parse input 0
inp_txid_le = raw[off:off+32]; off += 32
inp_vout = struct.unpack('<I', raw[off:off+4])[0]; off += 4
inp_script_len = raw[off]; off += 1
inp_script = raw[off:off+inp_script_len]; off += inp_script_len
inp_sequence = raw[off:off+4]; off += 4

print(f"Input txid (display): {inp_txid_le[::-1].hex()}")
print(f"Input vout: {inp_vout}")
print(f"ScriptSig length: {inp_script_len}")

# Parse scriptSig: <push_len> <sig_with_sighash> <push_len> <pubkey>
sig_push_len = inp_script[0]
sig_with_sighash = inp_script[1:1+sig_push_len]
pubkey_push_len = inp_script[1+sig_push_len]
pubkey = inp_script[1+sig_push_len+1:1+sig_push_len+1+pubkey_push_len]

der_sig = sig_with_sighash[:-1]
sighash_byte = sig_with_sighash[-1]

print(f"\nDER signature ({len(der_sig)} bytes): {der_sig.hex()}")
print(f"SIGHASH byte: 0x{sighash_byte:02x}")
print(f"Public key ({len(pubkey)} bytes): {pubkey.hex()}")

# Parse outputs
num_outputs = raw[off]; off += 1
outputs = []
for i in range(num_outputs):
    value = struct.unpack('<q', raw[off:off+8])[0]; off += 8
    script_len = raw[off]; off += 1
    script = raw[off:off+script_len]; off += script_len
    outputs.append({'value': value, 'script': script})
    print(f"\nOutput {i}: value={value}, script_len={script_len}")

locktime = struct.unpack('<I', raw[off:off+4])[0]
print(f"\nLocktime: {locktime}")

# === Now compute BIP143 preimage ===
print("\n=== BIP143 Preimage Computation ===")

# hashPrevouts
prevouts = inp_txid_le + struct.pack('<I', inp_vout)
hash_prevouts = double_sha256(prevouts)
print(f"hashPrevouts: {hash_prevouts.hex()}")

# hashSequence
hash_sequence = double_sha256(inp_sequence)
print(f"hashSequence: {hash_sequence.hex()}")

# hashOutputs
outputs_serialized = b''
for out in outputs:
    outputs_serialized += struct.pack('<q', out['value'])
    outputs_serialized += bytes([len(out['script'])]) + out['script']
hash_outputs = double_sha256(outputs_serialized)
print(f"hashOutputs: {hash_outputs.hex()}")

# scriptCode (P2PKH)
pubkey_hash = hash160(pubkey)
script_code = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
print(f"scriptCode: {script_code.hex()}")
print(f"pubkey_hash: {pubkey_hash.hex()}")

# Build preimage
preimage = b''
preimage += struct.pack('<I', version)           # nVersion
preimage += hash_prevouts                         # hashPrevouts
preimage += hash_sequence                         # hashSequence
preimage += inp_txid_le                           # outpoint txid
preimage += struct.pack('<I', inp_vout)           # outpoint vout
preimage += bytes([len(script_code)]) + script_code  # scriptCode
preimage += struct.pack('<q', UTXO_SATOSHIS)      # amount
preimage += struct.pack('<I', 0xffffffff)          # nSequence
preimage += hash_outputs                           # hashOutputs
preimage += struct.pack('<I', locktime)            # nLockTime
preimage += struct.pack('<I', 0x41)                # nHashType

print(f"\nPreimage length: {len(preimage)} bytes")
print(f"Preimage hex: {preimage.hex()}")

# Hash the preimage
tx_hash = double_sha256(preimage)
print(f"\nTransaction hash: {tx_hash.hex()}")

# Verify signature
private_key = ec.derive_private_key(
    int.from_bytes(bytes.fromhex(PRIVATE_KEY), 'big'),
    ec.SECP256K1(),
    default_backend()
)

# Also derive public key from private key and compare with the one in scriptSig
derived_pubkey = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)
print(f"\nDerived pubkey:  {derived_pubkey.hex()}")
print(f"ScriptSig pubkey: {pubkey.hex()}")
print(f"Match: {derived_pubkey == pubkey}")

# Verify the signature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
# Parse DER signature
if der_sig[0] != 0x30:
    print("ERROR: Not a DER signature")
else:
    seq_len = der_sig[1]
    off2 = 2
    if der_sig[off2] != 0x02:
        print("ERROR: Expected INTEGER tag for R")
    else:
        r_len = der_sig[off2+1]
        r = int.from_bytes(der_sig[off2+2:off2+2+r_len], 'big')
        off2 += 2 + r_len
        if der_sig[off2] != 0x02:
            print("ERROR: Expected INTEGER tag for S")
        else:
            s_len = der_sig[off2+1]
            s = int.from_bytes(der_sig[off2+2:off2+2+s_len], 'big')
            
            print(f"\nR: {r}")
            print(f"S: {s}")
            
            # Check low-S
            N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            print(f"S < N/2: {s < N // 2}")
            
            # Verify using cryptography library
            dss_sig = encode_dss_signature(r, s)
            try:
                public_key = private_key.public_key()
                public_key.verify(dss_sig, tx_hash, ec.ECDSA(hashes.SHA256()))
                print("\n✅ SIGNATURE VERIFIES AGAINST BIP143 PREIMAGE!")
            except Exception as e:
                print(f"\n❌ SIGNATURE DOES NOT VERIFY: {e}")

# Now let's also try broadcasting this transaction via ARC
print("\n=== Trying ARC Broadcast ===")
import requests
try:
    # WhatsonChain broadcast
    resp = requests.post(
        "https://api.whatsonchain.com/v1/bsv/main/tx/raw",
        json={"txhex": TX_HEX},
        timeout=30
    )
    print(f"WoC Status: {resp.status_code}")
    print(f"WoC Response: {resp.text[:500]}")
except Exception as e:
    print(f"WoC Error: {e}")

# Try ARC
try:
    resp2 = requests.post(
        "https://arc.taal.com/tx",
        headers={"Content-Type": "application/octet-stream"},
        data=bytes.fromhex(TX_HEX),
        timeout=30
    )
    print(f"\nARC Status: {resp2.status_code}")
    print(f"ARC Response: {resp2.text[:500]}")
except Exception as e:
    print(f"ARC Error: {e}")
