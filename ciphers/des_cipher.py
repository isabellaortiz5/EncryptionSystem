import random
from typing import List
from utils.file_io import save_key_to_file, load_key_from_file
from utils.des_utils import DESUtils

class DESCipher:

    def __init__(self):
        self.utils = DESUtils()

    def generate_key(self) -> int:
        key = random.getrandbits(56)
        key = key << 8
        return key

    def encrypt_block(self, block: int, key: int) -> int:
        subkeys = self.utils.generate_subkeys(key)
        block = self.utils.permute(block, self.utils.IP, 64)
        left = (block >> 32) & 0xFFFFFFFF
        right = block & 0xFFFFFFFF
        
        for subkey in subkeys:
            prev_right = right
            right = left ^ self.utils.f_function(right, subkey)
            left = prev_right
            
        block = (right << 32) | left
        return self.utils.permute(block, self.utils.IP_INV, 64)

    def decrypt_block(self, block: int, key: int) -> int:
        subkeys = self.utils.generate_subkeys(key)
        
        block = self.utils.permute(block, self.utils.IP, 64)
        
        left = (block >> 32) & 0xFFFFFFFF
        right = block & 0xFFFFFFFF
        
        for subkey in reversed(subkeys):
            prev_right = right
            right = left ^ self.utils.f_function(right, subkey)
            left = prev_right
            
        block = (right << 32) | left
        return self.utils.permute(block, self.utils.IP_INV, 64)

    def encrypt(self, plaintext: str, key: int) -> bytes:
        data = plaintext.encode('utf-8')
        padded_data = self._pad_data(data)
        
        result = bytearray()
        for i in range(0, len(padded_data), 8):
            block = int.from_bytes(padded_data[i:i+8], 'big')
            encrypted_block = self.encrypt_block(block, key)
            result.extend(encrypted_block.to_bytes(8, 'big'))
            
        return bytes(result)

    def decrypt(self, ciphertext: bytes, key: int) -> str:
        if len(ciphertext) % 8 != 0:
            raise ValueError("Ciphertext length must be a multiple of 8 bytes")
        
        result = bytearray()

        for i in range(0, len(ciphertext), 8):
            block = int.from_bytes(ciphertext[i:i+8], 'big')
            decrypted_block = self.decrypt_block(block, key)
            result.extend(decrypted_block.to_bytes(8, 'big'))
            
        unpadded = self._unpad_data(bytes(result))
        return unpadded.decode('utf-8')

    def _pad_data(self, data: bytes) -> bytes:
        block_size = 8
        pad_length = block_size - (len(data) % block_size)
        padding = bytes([pad_length] * pad_length)
        return data + padding

    def _unpad_data(self, data: bytes) -> bytes:
        pad_length = data[-1]
        if pad_length > 8:
            raise ValueError("Invalid padding")
        for i in range(1, pad_length + 1):
            if data[-i] != pad_length:
                raise ValueError("Invalid padding")
        return data[:-pad_length]

    def save_key(self, key: int, filename: str):
        save_key_to_file({'key': key}, 'des', filename)

    def load_key(self, filename: str) -> int:
        data = load_key_from_file(filename)
        if data['cipher_type'] != 'des':
            raise ValueError("Invalid key file type")
        return data['key_data']['key']
