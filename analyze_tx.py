"""Analyze the Python-generated transaction in detail."""

import struct

# Python生成的交易hex
tx_hex = "01000000019417ad02a47df611f75bd2b8f5acf3a5615211978e0872caaffb0d29ec97beb6010000006a473044022072fc2b0be0728314651fe3df6e4f1bf410f7ee7b39ea29034ca724855f1c79c002202c32712af7b30b369d952947b0419ec4d14e812956a96d6df6f87e52ae149a9c4121024483ccc23e3df5a9de9e1e33a9998ba79056b5a3353af91442b2805009a149a4ffffffff02000000000000000025006a224d696e675365616c2054657374205858585858585858585858585858585858585858282b0700000000001976a914b3f1eb0f62bf2e171bbba5638c7cc5e80345b8e188ac00000000"

raw = bytes.fromhex(tx_hex)
print(f"Transaction raw length: {len(raw)} bytes")
print(f"Hex string length: {len(tx_hex)} characters")
print()

# Parse transaction
offset = 0

# Version
version = struct.unpack('<I', raw[offset:offset+4])[0]
print(f"[{offset:3d}-{offset+4:3d}] Version: {version}")
offset += 4

# Input count
num_inputs = raw[offset]
print(f"[{offset:3d}] Input count: {num_inputs}")
offset += 1

# Parse input 0
print(f"\n--- Input 0 ---")
prev_txid = raw[offset:offset+32][::-1].hex()
print(f"[{offset:3d}-{offset+32:3d}] Previous TXID: {prev_txid}")
offset += 32

vout = struct.unpack('<I', raw[offset:offset+4])[0]
print(f"[{offset:3d}-{offset+4:3d}] Vout: {vout}")
offset += 4

script_sig_len = raw[offset]
print(f"[{offset:3d}] ScriptSig length: {script_sig_len}")
offset += 1

script_sig = raw[offset:offset+script_sig_len]
print(f"[{offset:3d}-{offset+script_sig_len:3d}] ScriptSig: {script_sig.hex()}")
print(f"  ScriptSig breakdown:")
sig = script_sig[:script_sig_len-33-1]  # sig + sighash + pubkey prefix
pubkey_len = script_sig[script_sig_len-33]
pubkey = script_sig[script_sig_len-33+1:]
print(f"    Sig push length: {script_sig_len - 33 - 1}")
print(f"    DER sig: {sig.hex()}")
print(f"    SIGHASH byte: 0x{sig[-1]:02x}")
print(f"    Pubkey push length: {pubkey_len}")
print(f"    Pubkey: {pubkey.hex()}")
offset += script_sig_len

sequence = struct.unpack('<I', raw[offset:offset+4])[0]
print(f"[{offset:3d}-{offset+4:3d}] Sequence: 0x{sequence:08x}")
offset += 4

# Output count
num_outputs = raw[offset]
print(f"\n[{offset:3d}] Output count: {num_outputs}")
offset += 1

# Output 0 (OP_RETURN)
print(f"\n--- Output 0 (OP_RETURN) ---")
value0 = struct.unpack('<q', raw[offset:offset+8])[0]
print(f"[{offset:3d}-{offset+8:3d}] Value: {value0} satoshis")
offset += 8

script0_len = raw[offset]
print(f"[{offset:3d}] Script length: {script0_len}")
offset += 1

script0 = raw[offset:offset+script0_len]
print(f"[{offset:3d}-{offset+script0_len:3d}] Script: {script0.hex()}")
print(f"  Decoded: ", end="")
for b in script0:
    if b == 0x00:
        print("OP_FALSE ", end="")
    elif b == 0x6a:
        print("OP_RETURN ", end="")
    elif b >= 0x01 and b <= 0x4b:
        print(f"DATA({b} bytes) ", end="")
    else:
        print(f"0x{b:02x} ", end="")
print()
offset += script0_len

# Output 1 (P2PKH change)
print(f"\n--- Output 1 (P2PKH change) ---")
value1 = struct.unpack('<q', raw[offset:offset+8])[0]
print(f"[{offset:3d}-{offset+8:3d}] Value: {value1} satoshis")
offset += 8

script1_len = raw[offset]
print(f"[{offset:3d}] Script length: {script1_len}")
offset += 1

script1 = raw[offset:offset+script1_len]
print(f"[{offset:3d}-{offset+script1_len:3d}] Script: {script1.hex()}")
offset += script1_len

# Locktime
locktime = struct.unpack('<I', raw[offset:offset+4])[0]
print(f"\n[{offset:3d}-{offset+4:3d}] Locktime: {locktime}")
offset += 4

print(f"\nTotal bytes parsed: {offset}")
print(f"Remaining: {len(raw) - offset}")

# Check DER signature
print("\n=== DER Signature Analysis ===")
der_sig = sig[:-1]  # Remove SIGHASH byte
sighash = sig[-1]
print(f"DER signature (len={len(der_sig)}): {der_sig.hex()}")
print(f"SIGHASH byte: 0x{sighash:02x}")
print(f"  SIGHASH_ALL = 0x01")
print(f"  SIGHASH_FORKID = 0x40")
print(f"  Combined = 0x41")
print(f"  Is SIGHASH_FORKID? {sighash == 0x41}")
