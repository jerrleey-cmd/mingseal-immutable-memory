"""Verify BIP143 preimage against the ACTUAL successful transaction with correct parent."""

import struct
from src.mingseal_immutable_memory.core.bsv_tx import double_sha256, hash160
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# The successful transaction
SUCCESS_TX_HEX = "010000000194656ef2d80edc35cd122f73ab6f9b17fae8555cf664e0bdb04ba4f47442235b010000006a47304402200cf196fca5d8e6c3ade41f54b68b826798f0bbbe8238318ab03ed1b932aa76960220796cf7599fe6160504742638ede2ee330e0b1c3fbb02e17b4bb2d4263f13a47f4121024483ccc23e3df5a9de9e1e33a9998ba79056b5a3353af91442b2805009a149a4ffffffff02000000000000000028006a044d534c4c20ca35c4f3c976129e4f88cd04e4eaca57a9a7b9cd9218a0a3340266026492a721f4540700000000001976a914b3f1eb0f62bf2e171bbba5638c7cc5e80345b8e188ac00000000"

# The CORRECT parent transaction (5b234274...)
PARENT_TX_HEX = "01000000013e38460ec3cab03b52ccdde6516aa1001ab1ad10df4c0234df936ac76651c93d010000006a473044022008716d69ece04da3f41b5cbc879a53e65f8ecd4bc16968872d88566ff2e801ff02203b8a45ca3a73d8a22f9d3b3cc893fe2b3742134eb90a1d695b023d5488ce657c4121024483ccc23e3df5a9de9e1e33a9998ba79056b5a3353af91442b2805009a149a4ffffffff02000000000000000028006a044d534c4c200b2bbb752159235b626040385a5040f0db3c3ddb45cb1504af90698ea73a08fadc580700000000001976a914b3f1eb0f62bf2e171bbba5638c7cc5e80345b8e188ac00000000"

PRIVATE_KEY = "f9edfeebc7b10d098e37af4884daace0254039fb02dbc1172e8d1ce57d3641b2"

# Parse parent to get UTXO value
parent_raw = bytes.fromhex(PARENT_TX_HEX)
off = 4
n_in = parent_raw[off]; off += 1
for i in range(n_in):
    off += 32 + 4
    script_len = parent_raw[off]; off += 1
    off += script_len
    off += 4
n_out = parent_raw[off]; off += 1
for i in range(n_out):
    value = struct.unpack('<q', parent_raw[off:off+8])[0]; off += 8
    script_len = parent_raw[off]; off += 1
    script = parent_raw[off:off+script_len]; off += script_len
    print(f"Parent output {i}: value={value} sat, script={script.hex()[:40]}...")

UTXO_SATOSHIS = 481500  # output 1 of the parent
print(f"\nUTXO value: {UTXO_SATOSHIS} satoshis")

# Parse the successful transaction
raw = bytes.fromhex(SUCCESS_TX_HEX)
off = 0
version = struct.unpack('<I', raw[off:off+4])[0]; off += 4
n_in = raw[off]; off += 1
inp_txid_le = raw[off:off+32]; off += 32
inp_vout = struct.unpack('<I', raw[off:off+4])[0]; off += 4
inp_script_len = raw[off]; off += 1
inp_script = raw[off:off+inp_script_len]; off += inp_script_len
inp_sequence = raw[off:off+4]; off += 4

# Parse scriptSig
sig_push_len = inp_script[0]
sig_with_sighash = inp_script[1:1+sig_push_len]
pubkey_push_len = inp_script[1+sig_push_len]
pubkey = inp_script[1+sig_push_len+1:1+sig_push_len+1+pubkey_push_len]
der_sig = sig_with_sighash[:-1]
sighash_byte = sig_with_sighash[-1]

# Parse outputs
n_out = raw[off]; off += 1
outputs = []
for i in range(n_out):
    value = struct.unpack('<q', raw[off:off+8])[0]; off += 8
    script_len = raw[off]; off += 1
    script = raw[off:off+script_len]; off += script_len
    outputs.append({'value': value, 'script': script})
locktime = struct.unpack('<I', raw[off:off+4])[0]

# === Compute BIP143 preimage ===
prevouts = inp_txid_le + struct.pack('<I', inp_vout)
hash_prevouts = double_sha256(prevouts)
hash_sequence = double_sha256(inp_sequence)
outputs_serialized = b''
for out in outputs:
    outputs_serialized += struct.pack('<q', out['value'])
    outputs_serialized += bytes([len(out['script'])]) + out['script']
hash_outputs = double_sha256(outputs_serialized)
pubkey_hash = hash160(pubkey)
script_code = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

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

tx_hash = double_sha256(preimage)

# Parse and verify signature
if der_sig[0] == 0x30:
    off2 = 2
    r_len = der_sig[off2+1]; r = int.from_bytes(der_sig[off2+2:off2+2+r_len], 'big'); off2 += 2 + r_len
    s_len = der_sig[off2+1]; s = int.from_bytes(der_sig[off2+2:off2+2+s_len], 'big')

    private_key = ec.derive_private_key(
        int.from_bytes(bytes.fromhex(PRIVATE_KEY), 'big'),
        ec.SECP256K1(), default_backend()
    )
    
    dss_sig = encode_dss_signature(r, s)
    try:
        private_key.public_key().verify(dss_sig, tx_hash, ec.ECDSA(hashes.SHA256()))
        print("\n✅ BIP143 SIGNATURE VERIFIES WITH CORRECT UTXO VALUE!")
        print("Our BIP143 implementation is CORRECT!")
    except Exception as e:
        print(f"\n❌ STILL DOESN'T VERIFY: {e}")
        
        # Maybe try without OP_0 prefix in the OP_RETURN script?
        print("\n=== Try different hashOutputs (without OP_0) ===")
        # Reconstruct outputs without OP_0
        outputs_v2 = []
        for i, out in enumerate(outputs):
            script = out['script']
            if script[0:2] == b'\x00\x6a':
                # Remove OP_0 prefix
                script = script[1:]  # Remove the 0x00 byte
                print(f"  Output {i}: removed OP_0, new script: {script.hex()}")
            outputs_v2.append({'value': out['value'], 'script': script})
        
        outputs_v2_serialized = b''
        for out in outputs_v2:
            outputs_v2_serialized += struct.pack('<q', out['value'])
            outputs_v2_serialized += bytes([len(out['script'])]) + out['script']
        hash_outputs_v2 = double_sha256(outputs_v2_serialized)
        
        preimage_v2 = preimage[:-(32+4+4)]  # Remove hashOutputs + locktime + sighash
        preimage_v2 += hash_outputs_v2
        preimage_v2 += struct.pack('<I', locktime)
        preimage_v2 += struct.pack('<I', 0x41)
        
        tx_hash_v2 = double_sha256(preimage_v2)
        try:
            private_key.public_key().verify(dss_sig, tx_hash_v2, ec.ECDSA(hashes.SHA256()))
            print("✅ WORKS WITHOUT OP_0! The OP_0 prefix in OP_RETURN is the bug!")
        except Exception as e2:
            print(f"❌ Still doesn't work: {e2}")
            
            # Try with the output scripts as-is but without varint for scriptCode
            print("\n=== Try without varint prefix on scriptCode ===")
            preimage_v3 = b''
            preimage_v3 += struct.pack('<I', version)
            preimage_v3 += hash_prevouts
            preimage_v3 += hash_sequence
            preimage_v3 += inp_txid_le
            preimage_v3 += struct.pack('<I', inp_vout)
            preimage_v3 += script_code  # NO varint prefix
            preimage_v3 += struct.pack('<q', UTXO_SATOSHIS)
            preimage_v3 += struct.pack('<I', 0xffffffff)
            preimage_v3 += hash_outputs
            preimage_v3 += struct.pack('<I', locktime)
            preimage_v3 += struct.pack('<I', 0x41)
            
            tx_hash_v3 = double_sha256(preimage_v3)
            try:
                private_key.public_key().verify(dss_sig, tx_hash_v3, ec.ECDSA(hashes.SHA256()))
                print("✅ WORKS WITHOUT VARINT ON SCRIPTCODE!")
            except Exception as e3:
                print(f"❌ Still doesn't work")
                
                # Let me dump the preimage for manual debugging
                print(f"\nPreimage hex: {preimage.hex()}")
                print(f"tx_hash: {tx_hash.hex()}")
                print(f"R={r}")
                print(f"S={s}")
