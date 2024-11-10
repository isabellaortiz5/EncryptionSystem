import random
from typing import Dict
import string
from ..utils.file_io import save_key_to_file, load_key_from_file
from ..hacking.analysis import TextAnalysis

class MonoalphabeticCipher:
    """
    Implementation of the Monoalphabetic Substitution Cipher with support for 
    both English and Spanish alphabets.
    """
    
    def __init__(self, language: str = 'en'):
        """
        Initialize the Monoalphabetic Cipher.
        
        Args:
            language: Language code ('en' for English or 'es' for Spanish)
        """
        self.alphabets = {
            'en': string.ascii_uppercase,  # 26 letters
            'es': "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"  # 27 letters
        }
        self.alphabet = self.alphabets.get(language, self.alphabets['en'])
        self.language = language
        self.substitution_map: Dict[str, str] = {}
        self.reverse_map: Dict[str, str] = {}
        self.analysis = TextAnalysis(language)

    def generate_key(self) -> Dict[str, str]:
        """Generate a random substitution key."""
        alphabet_list = list(self.alphabet)
        shuffled = alphabet_list.copy()
        random.shuffle(shuffled)
        
        self.substitution_map = dict(zip(alphabet_list, shuffled))
        self.reverse_map = {v: k for k, v in self.substitution_map.items()}
        
        return self.substitution_map

    def set_key(self, substitution_map: Dict[str, str]):
        """
        Set the substitution key manually.
        
        Args:
            substitution_map: Dictionary mapping plaintext to ciphertext characters
        """
        # Verify the key contains all alphabet characters
        if not all(c in substitution_map for c in self.alphabet):
            raise ValueError(f"Substitution map must contain all characters in the {self.language} alphabet")
        if len(set(substitution_map.values())) != len(self.alphabet):
            raise ValueError("Substitution map must not contain duplicate values")
            
        self.substitution_map = substitution_map
        self.reverse_map = {v: k for k, v in substitution_map.items()}

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using the current substitution map.
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Encrypted text
        """
        if not self.substitution_map:
            self.generate_key()
            
        ciphertext = ''
        for char in plaintext.upper():
            if char in self.alphabet:
                ciphertext += self.substitution_map[char]
            else:
                ciphertext += char
        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using the current reverse substitution map.
        
        Args:
            ciphertext: Text to decrypt
            
        Returns:
            Decrypted text
        """
        if not self.reverse_map:
            if self.substitution_map:
                self.reverse_map = {v: k for k, v in self.substitution_map.items()}
            else:
                raise ValueError("No decryption key available")
                
        plaintext = ''
        for char in ciphertext.upper():
            if char in self.alphabet:
                plaintext += self.reverse_map[char]
            else:
                plaintext += char
        return plaintext

    def analyze_frequency(self, text: str) -> Dict[str, float]:
        """Perform frequency analysis on the text."""
        return dict(self.analysis.frequency_analysis(text))

    def save_key(self, filename: str):
        """Save the current key to a file."""
        key_data = {
            'substitution_map': self.substitution_map,
            'language': self.language
        }
        save_key_to_file(key_data, 'monoalphabetic', filename)

    def load_key(self, filename: str):
        """Load a key from a file."""
        data = load_key_from_file(filename)
        if data['cipher_type'] != 'monoalphabetic':
            raise ValueError("Invalid key file type")
        
        # Update language if needed
        self.language = data['key_data']['language']
        self.alphabet = self.alphabets[self.language]
        self.set_key(data['key_data']['substitution_map'])