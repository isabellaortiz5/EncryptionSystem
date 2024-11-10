import random
from typing import List
from ..utils.file_io import save_key_to_file, load_key_from_file
from ..utils.des_utils import DESUtils

class DESCipher:
    """
    Full implementation of the Data Encryption Standard (DES) cipher.
    Uses 56-bit key length and performs proper permutations and substitutions.
    """
    
    def __init__(self):
        """Initialize the DES cipher."""
        self.utils = DESUtils()

    def generate_key(self) -> int:
        """Generate a random 56-bit key (stored as 64 bits with parity)."""
        # Generate 56 random bits
        key = random.getrandbits(56)
        # Add parity bits (for compatibility, not enforcing actual parity)
        key = key << 8
        return key

    def encrypt_block(self, block: int, key: int) -> int:
        """
        Encrypt a 64-bit block using DES.
        
        Args:
            block: 64-bit integer block to encrypt
            key: 64-bit encryption key (including parity bits)
            
        Returns:
            64-bit encrypted block
        """
        # Generate subkeys
        subkeys = self.utils.generate_subkeys(key)
        
        # Initial permutation
        block = self.utils.permute(block, self.utils.IP, 64)
        
        # Split block into left and right halves
        left = (block >> 32) & 0xFFFFFFFF
        right = block & 0xFFFFFFFF
        
        # 16 rounds
        for subkey in subkeys:
            # Save previous right half
            prev_right = right
            # F-function on right half and XOR with left half
            right = left ^ self.utils.f_function(right, subkey)
            # Previous right half becomes new left half
            left = prev_right
            
        # Combine halves (switched) and apply final permutation
        block = (right << 32) | left
        return self.utils.permute(block, self.utils.IP_INV, 64)

    def decrypt_block(self, block: int, key: int) -> int:
        """
        Decrypt a 64-bit block using DES.
        
        Args:
            block: 64-bit integer block to decrypt
            key: 64-bit decryption key (including parity bits)
            
        Returns:
            64-bit decrypted block
        """
        # Generate subkeys
        subkeys = self.utils.generate_subkeys(key)
        
        # Initial permutation
        block = self.utils.permute(block, self.utils.IP, 64)
        
        # Split block into left and right halves
        left = (block >> 32) & 0xFFFFFFFF
        right = block & 0xFFFFFFFF
        
        # 16 rounds with reversed subkeys
        for subkey in reversed(subkeys):
            # Save previous right half
            prev_right = right
            # F-function on right half and XOR with left half
            right = left ^ self.utils.f_function(right, subkey)
            # Previous right half becomes new left half
            left = prev_right
            
        # Combine halves (switched) and apply final permutation
        block = (right << 32) | left
        return self.utils.permute(block, self.utils.IP_INV, 64)

    def encrypt(self, plaintext: str, key: int) -> bytes:
        """
        Encrypt a string using DES in ECB mode.
        
        Args:
            plaintext: String to encrypt
            key: 64-bit encryption key (including parity bits)
            
        Returns:
            Encrypted bytes
        """
        # Convert string to bytes and pad
        data = plaintext.encode('utf-8')
        padded_data = self._pad_data(data)
        
        result = bytearray()
        # Process each block
        for i in range(0, len(padded_data), 8):
            block = int.from_bytes(padded_data[i:i+8], 'big')
            encrypted_block = self.encrypt_block(block, key)
            result.extend(encrypted_block.to_bytes(8, 'big'))
            
        return bytes(result)

    def decrypt(self, ciphertext: bytes, key: int) -> str:
        """
        Decrypt bytes using DES in ECB mode.
        
        Args:
            ciphertext: Bytes to decrypt
            key: 64-bit decryption key (including parity bits)
            
        Returns:
            Decrypted string
        """
        if len(ciphertext) % 8 != 0:
            raise ValueError("Ciphertext length must be a multiple of 8 bytes")
        
        result = bytearray()
        
        # Process each block
        for i in range(0, len(ciphertext), 8):
            block = int.from_bytes(ciphertext[i:i+8], 'big')
            decrypted_block = self.decrypt_block(block, key)
            result.extend(decrypted_block.to_bytes(8, 'big'))
            
        # Remove padding and convert to string
        unpadded = self._unpad_data(bytes(result))
        return unpadded.decode('utf-8')

    def _pad_data(self, data: bytes) -> bytes:
        """
        Add PKCS7 padding to ensure data length is multiple of block size.
        """
        block_size = 8
        pad_length = block_size - (len(data) % block_size)
        padding = bytes([pad_length] * pad_length)
        return data + padding

    def _unpad_data(self, data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data.
        """
        pad_length = data[-1]
        if pad_length > 8:
            raise ValueError("Invalid padding")
        for i in range(1, pad_length + 1):
            if data[-i] != pad_length:
                raise ValueError("Invalid padding")
        return data[:-pad_length]

    def save_key(self, key: int, filename: str):
        """Save the DES key to a file."""
        save_key_to_file({'key': key}, 'des', filename)

    def load_key(self, filename: str) -> int:
        """Load a DES key from a file."""
        data = load_key_from_file(filename)
        if data['cipher_type'] != 'des':
            raise ValueError("Invalid key file type")
        return data['key_data']['key']
