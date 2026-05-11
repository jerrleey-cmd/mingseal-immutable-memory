"""Verify the BIP143 preimage against a KNOWN SUCCESSFUL transaction."""

import struct
from src.mingseal_immutable_memory.core.bsv_tx import double_sha256, hash160
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# The successful transaction from our address (created by daily_attestation.js using bsv library)
SUCCESS_TX_HEX = "010000000194656ef2d80edc35cd122f73ab6f9b17fae8555cf664e0bdb04ba4f47442235b010000006a47304402200cf196fca5d8e6c3ade41f54b68b826798f0bbbe8238318ab03ed1b932aa76960220796cf7599fe6160504742638ede2ee330e0b1c3fbb02e17b4bb2d4263f13a47f4121024483ccc23e3df5a9de9e1e33a9998ba79056b5a3353af91442b2805009a149a4ffffffff02000000000000000028006a044d534c4c20ca35c4f3c976129e4f88cd04e4eaca57a9a7b9cd9218a0a3340266026492a721f4540700000000001976a914b3f1eb0f62bf2e171bbba5638c7cc5e80345b8e188ac00000000"

# The UTXO this transaction spends
PARENT_TX_HEX = "010000000137d513a77c9de2a9356b689bd15cf7e31c823ceaa132d59e88802a2771357df8010000006b483045022100b4a713b9ebfc2ae34ece598dcbd0bf0c5f393b822634b1d57f0bb80fe1dac1a4022077065331dcabcc7c14e563e2b8ed67f03895b92f7c96fcd845d1f52ef26628d44121024483ccc23e3df5a9de9e1e33a9998ba79056b5a3353af91442b2805009a149a4ffffffff02000000000000000028006a044d534c4c201d73f2fabb930ac3e07632f0b74f51475df87713944d4931a21699572a01dc16102f0700000000001976a914b3f1eb0f62bf2e171bbba5638c7cc5e80345b8e188ac00000000"

PRIVATE_KEY = "f9edfeebc7b10d098e37af4884daace0254039fb02dbc1172e8d1ce57d3641b2"

# Parse parent transaction to get the UTXO value
parent_raw = bytes.fromhex(PARENT_TX_HEX)
off = 4  # skip version
n_in = parent_raw[off]; off += 1
# Skip input
for i in range(n_in):
    off += 32 + 4  # txid + vout
    script_len = parent_raw[off]; off += 1
    off += script_len  # scriptSig
    off += 4  # sequence
# Parse outputs
outputs_info = []
n_out = parent_raw[off]; off += 1
for i in range(n_out):
    value = struct.unpack('<q', parent_raw[off:off+8])[0]; off += 8
    script_len = parent_raw[off]; off += 1
    script = parent_raw[off:off+script_len]; off += script_len
    outputs_info.append({'value': value, 'script': script})
    print(f"Parent output {i}: value={value} sat, script={script.hex()}")

# The UTXO being spent is output 1 of the parent transaction
UTXO_SATOSHIS = outputs_info[1]['value']
print(f"\nUTXO value: {UTXO_SATOSHIS} satoshis")

# Parse the successful transaction
raw = bytes.fromhex(SUCCESS_TX_HEX)
off = 0
version = struct.unpack('<I', raw[off:off+4])[0]; off += 4
n_in = raw[off]; off += 1

# Parse input 0
inp_txid_le = raw[off:off+32]; off += 32
inp_vout = struct.unpack('<I', raw[off:off+4])[0]; off += 4
inp_script_len = raw[off]; off += 1
inp_script = raw[off:off+inp_script_len]; off += inp_script_len
inp_sequence = raw[off:off+4]; off += 4

print(f"\nInput txid (display): {inp_txid_le[::-1].hex()}")
print(f"Input vout: {inp_vout}")

# Parse scriptSig
sig_push_len = inp_script[0]
sig_with_sighash = inp_script[1:1+sig_push_len]
pubkey_push_len = inp_script[1+sig_push_len]
pubkey = inp_script[1+sig_push_len+1:1+sig_push_len+1+pubkey_push_len]

der_sig = sig_with_sighash[:-1]
sighash_byte = sig_with_sighash[-1]
print(f"DER signature: {der_sig.hex()}")
print(f"SIGHASH: 0x{sighash_byte:02x}")
print(f"Public key: {pubkey.hex()}")

# Parse outputs
n_out = raw[off]; off += 1
outputs = []
for i in range(n_out):
    value = struct.unpack('<q', raw[off:off+8])[0]; off += 8
    script_len = raw[off]; off += 1
    script = raw[off:off+script_len]; off += script_len
    outputs.append({'value': value, 'script': script})
    print(f"\nOutput {i}: value={value}, script_len={script_len}, script={script.hex()}")

locktime = struct.unpack('<I', raw[off:off+4])[0]
print(f"\nLocktime: {locktime}")

# === Compute BIP143 preimage ===
print("\n=== Computing BIP143 Preimage for Successful TX ===")

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

# scriptCode
pubkey_hash = hash160(pubkey)
script_code = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
print(f"scriptCode: {script_code.hex()}")

# Build preimage
preimage = b''
preimage += struct.pack('<I', version)
preimage += hash_prevouts
preimage += hash_sequence
preimage += inp_txid_le
preimage += struct.pack('<I', inp_vout)
preimage += bytes([len(script_code)]) + script_code
preimage += struct.pack('<q', UTXO_SATOSHIS)
preimage += struct.pack('<I', 0xffffffff)
preimage += hash_outputs
preimage += struct.pack('<I', locktime)
preimage += struct.pack('<I', 0x41)

print(f"\nPreimage length: {len(preimage)}")
print(f"Preimage: {preimage.hex()}")

# Hash and verify
tx_hash = double_sha256(preimage)
print(f"\nTransaction hash: {tx_hash.hex()}")

# Parse DER signature and verify
if der_sig[0] == 0x30:
    seq_len = der_sig[1]
    off2 = 2
    r_len = der_sig[off2+1]
    r = int.from_bytes(der_sig[off2+2:off2+2+r_len], 'big')
    off2 += 2 + r_len
    s_len = der_sig[off2+1]
    s = int.from_bytes(der_sig[off2+2:off2+2+s_len], 'big')

    print(f"R: {r}")
    print(f"S: {s}")

    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    print(f"S < N/2: {s < N // 2}")

    private_key = ec.derive_private_key(
        int.from_bytes(bytes.fromhex(PRIVATE_KEY), 'big'),
        ec.SECP256K1(),
        default_backend()
    )
    
    dss_sig = encode_dss_signature(r, s)
    try:
        public_key = private_key.public_key()
        public_key.verify(dss_sig, tx_hash, ec.ECDSA(hashes.SHA256()))
        print("\n✅ SIGNATURE VERIFIES! Our BIP143 implementation is correct!")
    except Exception as e:
        print(f"\n❌ SIGNATURE DOES NOT VERIFY: {e}")
        print("Our BIP143 implementation has a bug!")
        
        # Let's try with the old-style sighash (non-BIP143) to see if that's what the node uses
        print("\n=== Trying old-style sighash (non-BIP143) ===")
        # Build the old-style preimage (SIGHASH_ALL without FORKID)
        # This is the original Bitcoin sighash algorithm
        # Serialize the transaction with the input's scriptSig replaced by the subscript
        
        # Build unsigned transaction (with subscript in the input being signed)
        unsigned = b''
        unsigned += struct.pack('<I', version)
        unsigned += bytes([1])  # 1 input
        # Input 0
        unsigned += inp_txid_le
        unsigned += struct.pack('<I', inp_vout)
        unsigned += bytes([len(script_code)]) + script_code  # Replace scriptSig with subscript
        unsigned += struct.pack('<I', 0xffffffff)
        # Outputs
        unsigned += bytes([len(outputs)])
        for out in outputs:
            unsigned += struct.pack('<q', out['value'])
            unsigned += bytes([len(out['script'])]) + out['script']
        unsigned += struct.pack('<I', locktime)
        unsigned += struct.pack('<I', 0x01)  # SIGHASH_ALL
        
        old_hash = double_sha256(unsigned)
        print(f"Old-style hash: {old_hash.hex()}")
        
        try:
            public_key.verify(dss_sig, old_hash, ec.ECDSA(hashes.SHA256()))
            print("✅ Old-style sighash WORKS! Node is NOT using BIP143!")
        except:
            print("❌ Old-style doesn't work either")
