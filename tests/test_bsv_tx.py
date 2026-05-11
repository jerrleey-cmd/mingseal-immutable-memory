"""
Unit tests for the BSV transaction builder.
"""

import pytest
from mingseal_immutable_memory.core.bsv_tx import (
    double_sha256,
    hash160,
    base58_encode,
    BSVTransaction,
    build_and_sign_op_return_tx,
)


class TestHashFunctions:
    """Tests for hash utility functions."""
    
    def test_double_sha256(self):
        """Test double SHA-256 hash."""
        data = b"hello"
        result = double_sha256(data)
        
        assert len(result) == 32
        assert isinstance(result, bytes)
    
    def test_hash160(self):
        """Test RIPEMD160(SHA256) hash."""
        data = b"hello"
        result = hash160(data)
        
        assert len(result) == 20
        assert isinstance(result, bytes)
    
    def test_base58_encode(self):
        """Test Base58 encoding."""
        # Test with known value
        data = b'\x00' + b'\x00' * 19 + b'\x01'  # Mainnet P2PKH with 1 sat
        result = base58_encode(data)
        
        # Should produce a valid base58 string
        assert isinstance(result, str)
        assert len(result) > 0
        # Base58 should not contain 0, O, I, l
        assert '0' not in result
        assert 'O' not in result
        assert 'I' not in result
        assert 'l' not in result


class TestBSVTransaction:
    """Tests for BSV transaction building."""
    
    def test_transaction_creation(self):
        """Test creating a basic transaction."""
        tx = BSVTransaction()
        
        assert tx.version == 1
        assert len(tx.inputs) == 0
        assert len(tx.outputs) == 0
        assert tx.locktime == 0
    
    def test_add_input(self):
        """Test adding an input."""
        tx = BSVTransaction()
        tx.add_input("abcd" * 16, 0, 100000)
        
        assert len(tx.inputs) == 1
        assert tx.inputs[0]['txid'] == "abcd" * 16
        assert tx.inputs[0]['vout'] == 0
        assert tx.inputs[0]['satoshis'] == 100000
    
    def test_add_op_return_output(self):
        """Test adding OP_RETURN output."""
        tx = BSVTransaction()
        data = b"test data"
        tx.add_op_return_output(data)
        
        assert len(tx.outputs) == 1
        assert tx.outputs[0]['value'] == 0
        # Check script starts with OP_FALSE OP_RETURN (0x00 0x6a)
        assert tx.outputs[0]['script'][:2] == b'\x00\x6a'
    
    def test_add_p2pkh_output(self):
        """Test adding P2PKH output."""
        tx = BSVTransaction()
        address_hash = b'\x00' * 20
        tx.add_p2pkh_output(address_hash, 50000)
        
        assert len(tx.outputs) == 1
        assert tx.outputs[0]['value'] == 50000
        # Check script structure
        script = tx.outputs[0]['script']
        assert script[0] == 0x76  # OP_DUP
        assert script[1] == 0xa9  # OP_HASH160
        assert script[2] == 0x14  # Push 20 bytes
        assert script[23:25] == b'\x88\xac'  # OP_EQUALVERIFY OP_CHECKSIG
    
    def test_serialize_for_forkid(self):
        """Test serializing transaction for SIGHASH_FORKID signing (BIP143 style)."""
        tx = BSVTransaction()
        tx.add_input("abcd" * 16, 0, 100000)
        tx.add_op_return_output(b"test")
        
        # Just verify it doesn't crash
        subscript = b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'
        result = tx._serialize_for_forkid(0, subscript, 100000)
        
        assert len(result) > 0
        assert isinstance(result, bytes)
    
    def test_to_hex(self):
        """Test transaction serialization to hex."""
        tx = BSVTransaction()
        tx.add_input("abcd" * 16, 0, 100000)
        
        result = tx.to_hex()
        
        assert isinstance(result, str)
        assert len(result) % 2 == 0  # Hex string should have even length


class TestBuildAndSignOpReturn:
    """Tests for the complete transaction builder."""
    
    def test_insufficient_balance(self):
        """Test that insufficient balance raises error."""
        # Use a random key for testing
        test_key = "0000000000000000000000000000000000000000000000000000000000000001"
        
        with pytest.raises(ValueError, match="Insufficient UTXO"):
            build_and_sign_op_return_tx(
                private_key_hex=test_key,
                utxo_txid="abcd" * 16,
                utxo_vout=0,
                utxo_satoshis=500,  # Less than dust limit + fee
                op_return_data=b"test",
                change_address_hash=b'\x00' * 20,
                fee=1000,
            )
    
    def test_sufficient_balance(self):
        """Test transaction with sufficient balance."""
        # Use a random key for testing
        test_key = "0000000000000000000000000000000000000000000000000000000000000001"
        
        # This should not raise
        result = build_and_sign_op_return_tx(
            private_key_hex=test_key,
            utxo_txid="abcd" * 16,
            utxo_vout=0,
            utxo_satoshis=10000,  # Sufficient balance
            op_return_data=b"test data for OP_RETURN",
            change_address_hash=b'\x00' * 20,
            fee=1000,
        )
        
        # Result should be a hex string
        assert isinstance(result, str)
        assert len(result) > 0
        assert len(result) % 2 == 0


class TestOpReturnScriptFormat:
    """Tests for OP_RETURN script format."""
    
    def test_small_data_push(self):
        """Test small data push (< 76 bytes)."""
        tx = BSVTransaction()
        tx.add_op_return_output(b"x" * 50)
        
        script = tx.outputs[0]['script']
        # Should be: OP_FALSE OP_RETURN PUSH50 <50 bytes>
        assert script[0] == 0x00  # OP_0
        assert script[1] == 0x6a  # OP_RETURN
        assert script[2] == 0x32  # PUSH50 (0x32 = 50)
    
    def test_medium_data_push(self):
        """Test medium data push (76-255 bytes)."""
        tx = BSVTransaction()
        tx.add_op_return_output(b"x" * 100)
        
        script = tx.outputs[0]['script']
        # Should be: OP_FALSE OP_RETURN OP_PUSHDATA1 <len> <data>
        assert script[0] == 0x00  # OP_0
        assert script[1] == 0x6a  # OP_RETURN
        assert script[2] == 0x4c  # OP_PUSHDATA1
        assert script[3] == 100   # Length
    
    def test_large_data_push(self):
        """Test large data push (> 255 bytes)."""
        tx = BSVTransaction()
        tx.add_op_return_output(b"x" * 300)
        
        script = tx.outputs[0]['script']
        # Should be: OP_FALSE OP_RETURN OP_PUSHDATA2 <len_16> <data>
        assert script[0] == 0x00  # OP_0
        assert script[1] == 0x6a  # OP_RETURN
        assert script[2] == 0x4d  # OP_PUSHDATA2
        # Length is little-endian 16-bit
        import struct
        length = struct.unpack('<H', script[3:5])[0]
        assert length == 300
