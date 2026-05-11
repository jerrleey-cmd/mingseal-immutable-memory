"""Real BSV broadcast test using BSVWallet."""

import sys
import asyncio
sys.path.insert(0, 'src')

from mingseal_immutable_memory.core.bsv_tx import BSVWallet, build_and_sign_op_return_tx, hash160
from mingseal_immutable_memory.core.bsv_tx import BSVTransaction, double_sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Test private key
PRIVATE_KEY = "f9edfeebc7b10d098e37af4884daace0254039fb02dbc1172e8d1ce57d3641b2"
ADDRESS = "1HQTm7L2KXTmNTecedhFRnQqP98yU1GAD7"

async def main():
    print("=== BSV Real Broadcast Test ===\n")

    # Step 1: Get UTXOs using BSVWallet
    print("Step 1: Fetching UTXOs...")
    wallet = BSVWallet(PRIVATE_KEY)
    print(f"Wallet address: {wallet.address}")
    print(f"Expected address: {ADDRESS}")
    print(f"Match: {wallet.address == ADDRESS}")
    
    utxos = await wallet.get_utxos()
    print(f"Found {len(utxos)} UTXOs")

    if not utxos:
        print("ERROR: No UTXOs found!")
        return

    utxo = utxos[0]
    print(f"\nUsing UTXO:")
    print(f"  txid: {utxo['txid']}")
    print(f"  vout: {utxo['vout']}")
    print(f"  satoshis: {utxo['satoshis']}")

    # Step 2: Build and sign transaction
    print("\nStep 2: Building and signing transaction...")
    OP_RETURN_DATA = b"MingSeal Test " + b"X" * 20

    tx_hex = build_and_sign_op_return_tx(
        PRIVATE_KEY,
        utxo['txid'],
        utxo['vout'],
        utxo['satoshis'],
        OP_RETURN_DATA,
        wallet.pubkey_hash,
        fee=1000
    )

    print(f"\nTransaction hex ({len(tx_hex)//2} bytes):")
    print(tx_hex)

    # Calculate TXID
    txid = double_sha256(bytes.fromhex(tx_hex))[::-1].hex()
    print(f"\nTXID: {txid}")

    # Step 3: Broadcast
    print("\nStep 3: Broadcasting...")
    result = await wallet.broadcast(tx_hex)
    print(f"\nBroadcast result:")
    print(f"  Success: {result is not None}")
    if result:
        print(f"  TXID: {result}")
    else:
        print("  FAILED - No TXID returned")

if __name__ == "__main__":
    asyncio.run(main())
