"""
BSV Transaction Builder for OP_RETURN anchoring.

Pure Python implementation using only the `cryptography` library
for secp256k1 ECDSA signing. No external BSV SDK required.
"""

import hashlib
import struct
import logging
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)


def double_sha256(data: bytes) -> bytes:
    """Double SHA-256 hash (Bitcoin standard)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) - used for Bitcoin addresses."""
    # Python 3.13+ removed ripemd160 from hashlib
    # Use pycryptodome as the primary implementation
    from Crypto.Hash import RIPEMD160, SHA256
    sha = SHA256.new(data).digest()
    return RIPEMD160.new(sha).digest()


def base58_encode(data: bytes) -> str:
    """Base58 encoding for Bitcoin addresses."""
    # Base58 alphabet (Bitcoin variant)
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    # Convert to integer
    num = int.from_bytes(data, 'big')
    
    # Encode
    result = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        result = ALPHABET[remainder] + result
    
    # Add leading zeros
    for byte in data:
        if byte == 0:
            result = "1" + result
        else:
            break
    
    return result


class BSVTransaction:
    """
    Construct and sign a BSV transaction with OP_RETURN output.
    
    This is a minimal implementation focused on OP_RETURN anchoring:
    - 1 input (P2PKH UTXO)
    - 1 OP_RETURN output (data)
    - 1 change output (P2PKH)
    """
    
    def __init__(self):
        self.version = 1
        self.inputs = []  # [(prev_txid, vout, script_sig, sequence)]
        self.outputs = []  # [(value_sat, script_pubkey)]
        self.locktime = 0
    
    def add_input(self, txid: str, vout: int, satoshis: int):
        """Add an input (before signing)."""
        self.inputs.append({
            'txid': txid,
            'vout': vout,
            'satoshis': satoshis,
            'script_sig': b'',
        })
    
    def add_op_return_output(self, data: bytes):
        """Add an OP_RETURN output with the given data."""
        # OP_FALSE OP_RETURN <push_data>
        script = b'\x00\x6a'  # OP_0 OP_RETURN
        
        # Push data in chunks if needed (max 100KB per push)
        if len(data) <= 75:
            script += bytes([len(data)]) + data
        elif len(data) <= 255:
            script += b'\x4c' + bytes([len(data)]) + data
        else:
            script += b'\x4d' + struct.pack('<H', len(data)) + data
        
        self.outputs.append({
            'value': 0,
            'script': script,
        })
    
    def add_p2pkh_output(self, address_hash: bytes, satoshis: int):
        """Add a P2PKH output (change)."""
        # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        script = (
            b'\x76\xa9\x14' +  # OP_DUP OP_HASH160 PUSH20
            address_hash +
            b'\x88\xac'  # OP_EQUALVERIFY OP_CHECKSIG
        )
        self.outputs.append({
            'value': satoshis,
            'script': script,
        })
    
    def _serialize_for_forkid(self, input_index: int, subscript: bytes, satoshis: int) -> bytes:
        """
        Serialize transaction for SIGHASH_FORKID signing (BIP143 style).
        
        This is the signing algorithm used by BCH and BSV after the 2017 fork.
        SIGHASH_FORKID = 0x40 | SIGHASH_ALL = 0x41
        """
        # hashPrevouts = SHA256(SHA256(all outpoints))
        prevouts = b''
        for inp in self.inputs:
            prevouts += bytes.fromhex(inp['txid'])[::-1]
            prevouts += struct.pack('<I', inp['vout'])
        hash_prevouts = double_sha256(prevouts)
        
        # hashSequence = SHA256(SHA256(all nSequence))
        sequences = b''
        for _ in self.inputs:
            sequences += struct.pack('<I', 0xffffffff)
        hash_sequence = double_sha256(sequences)
        
        # hashOutputs = SHA256(SHA256(all outputs))
        outputs = b''
        for out in self.outputs:
            outputs += struct.pack('<q', out['value'])
            outputs += bytes([len(out['script'])]) + out['script']
        hash_outputs = double_sha256(outputs)
        
        # Build preimage for BIP143/SIGHASH_FORKID signing
        result = b''
        result += struct.pack('<I', self.version)          # nVersion
        result += hash_prevouts                              # hashPrevouts (32 bytes)
        result += hash_sequence                              # hashSequence (32 bytes)
        result += bytes.fromhex(self.inputs[input_index]['txid'])[::-1]  # outpoint txid (32 bytes)
        result += struct.pack('<I', self.inputs[input_index]['vout'])     # outpoint vout (4 bytes)
        result += bytes([len(subscript)]) + subscript        # scriptCode (varint + script)
        result += struct.pack('<q', satoshis)                # value (8 bytes, little-endian)
        result += struct.pack('<I', 0xffffffff)              # nSequence (4 bytes)
        result += hash_outputs                               # hashOutputs (32 bytes)
        result += struct.pack('<I', self.locktime)           # nLockTime (4 bytes)
        result += struct.pack('<I', 0x41)                    # sighash_type (4 bytes, little-endian = 0x41000000)
        
        return result
    
    def sign_input(self, input_index: int, private_key_bytes: bytes, satoshis: int) -> bytes:
        """
        Sign a transaction input using secp256k1 ECDSA with SIGHASH_FORKID.
        
        BSV requires SIGHASH_FORKID (0x41) and low-S normalized signatures.
        
        Args:
            input_index: Index of the input to sign
            private_key_bytes: The private key bytes
            satoshis: Value of the UTXO being spent (required for BIP143)
            
        Returns:
            DER-encoded signature with SIGHASH_FORKID byte appended (0x41)
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        
        # Derive private key and public key
        private_key = ec.derive_private_key(
            int.from_bytes(private_key_bytes, 'big'),
            ec.SECP256K1(),
            default_backend()
        )
        public_key = private_key.public_key()
        pub_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        pubkey_hash = hash160(pub_key_bytes)
        
        # P2PKH subscript: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        subscript = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
        
        # Serialize with BIP143/SIGHASH_FORKID
        preimage = self._serialize_for_forkid(input_index, subscript, satoshis)
        tx_hash = double_sha256(preimage)
        
        # Sign with ECDSA
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        der_sig = private_key.sign(tx_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
        
        # Low-S normalization (BSV requirement)
        der_sig = self._normalize_signature_s(der_sig)
        
        # Append SIGHASH_FORKID byte (0x41 = SIGHASH_ALL | SIGHASH_FORKID)
        return der_sig + b'\x41'
    
    def _normalize_signature_s(self, der_sig: bytes) -> bytes:
        """
        Normalize the S value in a DER signature to low-S form.
        
        BSV requires low-S signatures (S < N/2 where N is secp256k1 order).
        If S > N/2, replace S with N - S.
        
        DER format: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
        """
        # secp256k1 order N
        N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        N_OVER_2 = N // 2
        
        # Parse DER signature
        if der_sig[0] != 0x30:
            return der_sig  # Not DER format, return as-is
        
        # Position after 30 <seq_len>
        offset = 2
        if der_sig[offset] != 0x02:
            return der_sig
        offset += 1  # Skip 02 tag
        
        r_len = der_sig[offset]
        offset += 1  # Skip r_len
        r = int.from_bytes(der_sig[offset:offset + r_len], 'big')
        offset += r_len  # Skip r value
        
        # Now at s INTEGER tag
        if der_sig[offset] != 0x02:
            return der_sig
        offset += 1  # Skip 02 tag
        
        s_len = der_sig[offset]
        offset += 1  # Skip s_len
        s = int.from_bytes(der_sig[offset:offset + s_len], 'big')
        
        # Low-S normalization
        if s > N_OVER_2:
            s = N - s
        
        # Re-encode as DER
        return self._encode_der_signature(r, s)
    
    def _encode_der_signature(self, r: int, s: int) -> bytes:
        """
        Encode r, s integers as DER-encoded ECDSA signature.
        
        Ensures strict DER encoding with MINIMUM bytes:
        - Integers are encoded in minimum bytes (DER requirement!)
        - If MSB is set (0x80+), prepend 0x00 to keep it positive
        - If there's a redundant leading 0x00, remove it (bsv-sdk compatibility)
        """
        def encode_int(v: int) -> bytes:
            if v == 0:
                return b'\x00'
            # Calculate minimum bytes needed
            bit_len = v.bit_length()
            byte_len = (bit_len + 7) // 8
            b = v.to_bytes(byte_len, 'big')
            # If first byte is 0x00, it means we can encode with fewer bytes
            # This is CRITICAL for bsv-sdk compatibility!
            while len(b) > 1 and b[0] == 0x00:
                b = b[1:]
            # DER requires 0x00 prefix only if MSB is set (to keep integer positive)
            if b[0] & 0x80:
                b = b'\x00' + b
            return b
        
        r_bytes = encode_int(r)
        s_bytes = encode_int(s)
        
        # Build DER sequence: 30 <total_len> 02 <r_len> <r> 02 <s_len> <s>
        r_part = b'\x02' + bytes([len(r_bytes)]) + r_bytes
        s_part = b'\x02' + bytes([len(s_bytes)]) + s_bytes
        sig_content = r_part + s_part
        
        return b'\x30' + bytes([len(sig_content)]) + sig_content
    
    def serialize(self) -> bytes:
        """Serialize the fully signed transaction."""
        result = b''
        
        # Version
        result += struct.pack('<I', self.version)
        
        # Input count (varint)
        result += bytes([len(self.inputs)])
        
        # Inputs
        for inp in self.inputs:
            txid_bytes = bytes.fromhex(inp['txid'])[::-1]
            result += txid_bytes
            result += struct.pack('<I', inp['vout'])
            script_sig = inp['script_sig']
            result += bytes([len(script_sig)]) + script_sig
            result += b'\xff\xff\xff\xff'  # sequence
        
        # Output count (varint)
        result += bytes([len(self.outputs)])
        
        # Outputs
        for out in self.outputs:
            result += struct.pack('<q', out['value'])
            result += bytes([len(out['script'])]) + out['script']
        
        # Locktime
        result += struct.pack('<I', self.locktime)
        
        return result
    
    def to_hex(self) -> str:
        """Return the serialized transaction as hex string."""
        return self.serialize().hex()


def build_and_sign_op_return_tx(
    private_key_hex: str,
    utxo_txid: str,
    utxo_vout: int,
    utxo_satoshis: int,
    op_return_data: bytes,
    change_address_hash: bytes,
    fee: int = 1000,
) -> str:
    """
    Build and sign a BSV transaction with OP_RETURN output.
    
    Args:
        private_key_hex: Private key in hex format
        utxo_txid: UTXO transaction ID
        utxo_vout: UTXO output index
        utxo_satoshis: UTXO value in satoshis
        op_return_data: Data to embed in OP_RETURN
        change_address_hash: Hash160 of change address (20 bytes)
        fee: Transaction fee in satoshis
        
    Returns:
        Signed transaction hex string
    """
    private_key_bytes = bytes.fromhex(private_key_hex)
    change_amount = utxo_satoshis - fee
    
    if change_amount < 546:
        raise ValueError(f"Insufficient UTXO balance: {utxo_satoshis} sat, need at least {fee + 546} sat")
    
    # Build transaction
    # Note: WhatsonChain API returns txid in display format (big-endian/bytes reversed)
    # We need to store it internally as-is since we reverse it during serialization
    tx = BSVTransaction()
    tx.add_input(utxo_txid, utxo_vout, utxo_satoshis)
    tx.add_op_return_output(op_return_data)
    tx.add_p2pkh_output(change_address_hash, change_amount)
    
    # Sign with SIGHASH_FORKID (requires satoshis for BIP143)
    sig = tx.sign_input(0, private_key_bytes, utxo_satoshis)
    
    # Get public key
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, 'big'),
        ec.SECP256K1(),
        default_backend()
    )
    pub_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    
    # Build scriptSig: <sig> <pubkey>
    script_sig = bytes([len(sig)]) + sig + bytes([len(pub_key_bytes)]) + pub_key_bytes
    tx.inputs[0]['script_sig'] = script_sig
    
    return tx.to_hex()


class BSVWallet:
    """
    Minimal BSV wallet for anchoring operations.
    
    Manages UTXO fetching and transaction broadcasting
    via WhatsonChain API.
    """
    
    WOC_API = "https://api.whatsonchain.com/v1/bsv/main"
    
    def __init__(self, private_key_hex: str, network: str = "main"):
        self._private_key_hex = private_key_hex
        self._network = network
        
        # Derive address from private key
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        private_key = ec.derive_private_key(
            int.from_bytes(bytes.fromhex(private_key_hex), 'big'),
            ec.SECP256K1(),
            default_backend()
        )
        pub_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        self._pub_key_hash = hash160(pub_key_bytes)
        self._address = self._hash_to_address(self._pub_key_hash)
        
        # Update API URL if testnet
        if network == "test":
            self.WOC_API = "https://api.whatsonchain.com/v1/bsv/test"
    
    def _hash_to_address(self, pubkey_hash: bytes) -> str:
        """Convert hash160 to Base58Check address."""
        # BSV mainnet version byte is 0x00
        versioned = b'\x00' + pubkey_hash
        checksum = double_sha256(versioned)[:4]
        payload = versioned + checksum
        
        # Base58 encode
        return base58_encode(payload)
    
    @property
    def address(self) -> str:
        return self._address
    
    @property  
    def pubkey_hash(self) -> bytes:
        return self._pub_key_hash
    
    @property
    def private_key_hex(self) -> str:
        return self._private_key_hex
    
    async def get_utxos(self) -> List[dict]:
        """Fetch UTXOs from WhatsonChain API."""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            url = f"{self.WOC_API}/address/{self._address}/unspent"
            async with session.get(url) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise ValueError(f"Failed to fetch UTXOs: HTTP {resp.status} - {text}")
                
                data = await resp.json()
                if not isinstance(data, list):
                    raise ValueError(f"Invalid UTXO response: {data}")
                
                return [
                    {
                        'txid': u['tx_hash'],
                        'vout': u['tx_pos'],
                        'satoshis': u['value'],
                    }
                    for u in data
                ]
    
    async def get_utxo(self) -> Optional[dict]:
        """Get the best UTXO for anchoring (largest non-dust)."""
        utxos = await self.get_utxos()
        
        # Filter out dust UTXOs and find a suitable one
        # Need at least fee + dust limit (546 sat for change)
        min_required = 1000 + 546
        for utxo in utxos:
            if utxo['satoshis'] >= min_required:
                return utxo
        
        return None
    
    async def broadcast(self, tx_hex: str) -> str:
        """Broadcast a signed transaction."""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            url = f"{self.WOC_API}/tx/raw"
            async with session.post(
                url,
                json={"txhex": tx_hex}
            ) as resp:
                result = await resp.text()
                
                # WhatsonChain returns the txid as a JSON string on success
                # Response might be: {"txid": "..."} or just "..."
                result = result.strip()
                
                # Try to extract txid from response
                if '"txid"' in result:
                    import json
                    data = json.loads(result)
                    return data.get('txid', result.strip('"'))
                
                # Check if result looks like a txid (64 hex chars)
                result_clean = result.strip('"').strip()
                if len(result_clean) == 64 and all(c in '0123456789abcdefABCDEF' for c in result_clean):
                    return result_clean
                
                # Otherwise it's an error
                raise ValueError(f"Broadcast failed: {result}")
    
    async def check_tx(self, txid: str) -> dict:
        """Check transaction status on chain."""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            url = f"{self.WOC_API}/tx/hash/{txid}"
            async with session.get(url) as resp:
                if resp.status == 404:
                    return {"confirmed": False, "found": False}
                return await resp.json()
    
    async def anchor(
        self,
        op_return_data: bytes,
        fee: int = 1000,
    ) -> Tuple[str, str]:
        """
        Create and broadcast an OP_RETURN anchoring transaction.
        
        Args:
            op_return_data: The data to embed in OP_RETURN
            fee: Transaction fee in satoshis
            
        Returns:
            Tuple of (txid, tx_hex)
        """
        # Get UTXO
        utxo = await self.get_utxo()
        if not utxo:
            raise ValueError(
                f"No suitable UTXO found. Need at least {fee + 546} satoshis. "
                f"Check wallet balance at {self._address}"
            )
        
        logger.info(f"Using UTXO: {utxo['txid']}:{utxo['vout']} ({utxo['satoshis']} sat)")
        
        # Build and sign transaction
        tx_hex = build_and_sign_op_return_tx(
            private_key_hex=self._private_key_hex,
            utxo_txid=utxo['txid'],
            utxo_vout=utxo['vout'],
            utxo_satoshis=utxo['satoshis'],
            op_return_data=op_return_data,
            change_address_hash=self._pub_key_hash,
            fee=fee,
        )
        
        # Broadcast
        txid = await self.broadcast(tx_hex)
        
        logger.info(f"Broadcasted transaction: {txid}")
        
        return txid, tx_hex
