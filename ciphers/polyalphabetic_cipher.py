import random
from typing import List, Tuple
import string
from utils.file_io import save_key_to_file, load_key_from_file
from hacking.analysis import TextAnalysis

class PolyalphabeticCipher:
    
    def __init__(self, language: str = 'en'):
        self.alphabets = {
            'en': string.ascii_uppercase,
            'es': "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
        }
        self.alphabet = self.alphabets.get(language, self.alphabets['en'])
        self.m = len(self.alphabet)
        self.language = language
        self.analysis = TextAnalysis(language)

    def generate_key(self, length: int) -> str:
        return ''.join(random.choice(self.alphabet) for _ in range(length))

    def encrypt(self, plaintext: str, key: str) -> str:
        key_length = len(key)
        key_indices = [self.alphabet.index(k) for k in key.upper()]
        ciphertext = ''
        
        i = 0  
        for char in plaintext.upper():
            if char in self.alphabet:
                plain_idx = self.alphabet.index(char)
                key_idx = key_indices[i % key_length]
                cipher_idx = (plain_idx + key_idx) % self.m
                ciphertext += self.alphabet[cipher_idx]
                i += 1
            else:
                ciphertext += char
                
        return ciphertext

    def decrypt(self, ciphertext: str, key: str) -> str:
        key_length = len(key)
        key_indices = [self.alphabet.index(k) for k in key.upper()]
        plaintext = ''
        
        i = 0  
        for char in ciphertext.upper():
            if char in self.alphabet:
                cipher_idx = self.alphabet.index(char)
                key_idx = key_indices[i % key_length]
                plain_idx = (cipher_idx - key_idx) % self.m
                plaintext += self.alphabet[plain_idx]
                i += 1
            else:
                plaintext += char
                
        return plaintext

    # def analyze_key_length(self, ciphertext: str, max_length: int = 20) -> List[Tuple[int, float]]:
    #     """Analyze possible key lengths using Index of Coincidence."""
    #     return self.analysis.get_likely_key_lengths(ciphertext, max_length)

    def save_key(self, key: str, filename: str):
        key_data = {
            'key': key,
            'language': self.language
        }
        save_key_to_file(key_data, 'polyalphabetic', filename)

    def load_key(self, filename: str) -> str:
        data = load_key_from_file(filename)
        if data['cipher_type'] != 'polyalphabetic':
            raise ValueError("Invalid key file type")

        self.language = data['key_data']['language']
        self.alphabet = self.alphabets[self.language]
        self.m = len(self.alphabet)
        
        return data['key_data']['key']
