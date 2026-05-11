"""Debug script to analyze transaction serialization."""

import struct
from src.mingseal_immutable_memory.core.bsv_tx import (
    BSVTransaction, build_and_sign_op_return_tx, double_sha256, hash160
)

# Test data
PRIVATE_KEY = "f9edfeebc7b10d098e37af4884daace0254039fb02dbc1172e8d1ce57d3641b2"
UTXO_TXID = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
UTXO_VOUT = 0
UTXO_SATOSHIS = 100000

# Derive address hash from private key
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
print(f"Address hash: {address_hash.hex()}")

# Build transaction
op_return_data = b"test data for BSV OP_RETURN"
tx_hex = build_and_sign_op_return_tx(
    PRIVATE_KEY,
    UTXO_TXID,
    UTXO_VOUT,
    UTXO_SATOSHIS,
    op_return_data,
    address_hash,
    fee=1000
)

print(f"\nTransaction hex ({len(tx_hex)//2} bytes):")
print(tx_hex[:200] + "..." if len(tx_hex) > 200 else tx_hex)

# Now let's manually parse the transaction to verify
def parse_transaction(raw: bytes):
    """Parse and display transaction structure."""
    offset = 0
    print("\n=== Transaction Parser ===")
    
    # Version
    version = struct.unpack('<I', raw[offset:offset+4])[0]
    print(f"version: {version}")
    offset += 4
    
    # Input count
    num_inputs = raw[offset]
    print(f"num_inputs: {num_inputs}")
    offset += 1
    
    # Inputs
    for i in range(num_inputs):
        print(f"\nInput {i}:")
        txid = raw[offset:offset+32][::-1].hex()
        print(f"  txid: {txid}")
        offset += 32
        
        vout = struct.unpack('<I', raw[offset:offset+4])[0]
        print(f"  vout: {vout}")
        offset += 4
        
        script_len = raw[offset]
        print(f"  script_sig_len: {script_len}")
        offset += 1
        
        script_sig = raw[offset:offset+script_len].hex()
        print(f"  script_sig: {script_sig[:100]}..." if len(script_sig) > 100 else f"  script_sig: {script_sig}")
        offset += script_len
        
        sequence = struct.unpack('<I', raw[offset:offset+4])[0]
        print(f"  sequence: {sequence:08x}")
        offset += 4
        
        # Parse signature details
        sig = raw[offset-script_len:offset-script_len+script_len]
        print(f"  sig_len: {len(sig)}")
        if len(sig) > 0:
            print(f"  sig_hex: {sig.hex()}")
            # Check SIGHASH byte
            sighash_byte = sig[-1]
            print(f"  sighash_byte: 0x{sighash_byte:02x}")
            if sighash_byte == 0x41:
                print(f"  (SIGHASH_FORKID)")
    
    # Output count
    num_outputs = raw[offset]
    print(f"\nnum_outputs: {num_outputs}")
    offset += 1
    
    # Outputs
    for i in range(num_outputs):
        print(f"\nOutput {i}:")
        value = struct.unpack('<q', raw[offset:offset+8])[0]
        print(f"  value: {value}")
        offset += 8
        
        script_len = raw[offset]
        print(f"  script_len: {script_len}")
        offset += 1
        
        script = raw[offset:offset+script_len].hex()
        print(f"  script: {script}")
        offset += script_len
    
    # Locktime
    locktime = struct.unpack('<I', raw[offset:offset+4])[0]
    print(f"\nlocktime: {locktime}")
    offset += 4
    
    print(f"\nTotal bytes parsed: {offset}")
    print(f"Raw length: {len(raw)}")
    
    return offset

raw_tx = bytes.fromhex(tx_hex)
parse_transaction(raw_tx)

# Let's also check the BIP143 preimage
print("\n\n=== BIP143 Preimage Analysis ===")
tx2 = BSVTransaction()
tx2.add_input(UTXO_TXID, UTXO_VOUT, UTXO_SATOSHIS)
tx2.add_op_return_output(op_return_data)
tx2.add_p2pkh_output(address_hash, UTXO_SATOSHIS - 1000)

# Calculate preimage
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

pub_key_bytes_compressed = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)
pubkey_hash = hash160(pub_key_bytes_compressed)
subscript = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

preimage = tx2._serialize_for_forkid(0, subscript, UTXO_SATOSHIS)
print(f"Preimage length: {len(preimage)} bytes")
print(f"Preimage hex: {preimage.hex()}")

# Verify preimage structure
print("\nPreimage breakdown:")
off = 0
print(f"  version: {struct.unpack('<I', preimage[off:off+4])[0]} (4 bytes)")
off += 4
print(f"  hashPrevouts: {preimage[off:off+32].hex()} (32 bytes)")
off += 32
print(f"  hashSequence: {preimage[off:off+32].hex()} (32 bytes)")
off += 32
print(f"  outpoint txid: {preimage[off:off+32][::-1].hex()} (32 bytes, little-endian display)")
off += 32
print(f"  outpoint vout: {struct.unpack('<I', preimage[off:off+4])[0]} (4 bytes)")
off += 4
script_code_len = preimage[off]
print(f"  scriptCode len: {script_code_len} (1 byte)")
off += 1
print(f"  scriptCode: {preimage[off:off+script_code_len].hex()} ({script_code_len} bytes)")
off += script_code_len
print(f"  satoshis: {struct.unpack('<q', preimage[off:off+8])[0]} (8 bytes, little-endian)")
off += 8
print(f"  nSequence: {struct.unpack('<I', preimage[off:off+4])[0]:08x} (4 bytes)")
off += 4
print(f"  hashOutputs: {preimage[off:off+32].hex()} (32 bytes)")
off += 32
print(f"  nLockTime: {struct.unpack('<I', preimage[off:off+4])[0]} (4 bytes)")
off += 4
print(f"  sighash_type: 0x{struct.unpack('<I', preimage[off:off+4])[0]:08x} (4 bytes, little-endian)")
off += 4
print(f"Total: {off} bytes")
