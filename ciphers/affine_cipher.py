import string
import random
from typing import Tuple, List
from utils.file_io import save_key_to_file, load_key_from_file

class AffineCipher:
    """Implementation of the Affine Cipher with support for both English and Spanish alphabets."""
    
    def __init__(self, language: str = 'en'):
        """
        Initialize the Affine Cipher.
        
        Args:
            language: Language code ('en' for English or 'es' for Spanish)
        """
        # Define alphabets
        self.alphabets = {
            'en': string.ascii_uppercase,  # 26 letters
            'es': "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"  # 27 letters
        }
        self.alphabet = self.alphabets.get(language, self.alphabets['en'])
        self.m = len(self.alphabet)
        self.language = language
        self.valid_a_values = self._get_valid_a_values()

    def _get_valid_a_values(self) -> List[int]:
        """Get all valid 'a' values that are coprime with alphabet length."""
        return [a for a in range(1, self.m) if self._gcd(a, self.m) == 1]

    def _gcd(self, a: int, b: int) -> int:
        """Compute the greatest common divisor (GCD) of two numbers."""
        while b != 0:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Compute the modular inverse of a under modulo m using the Extended Euclidean Algorithm.
        
        Args:
            a: The number to find the modular inverse of
            m: The modulo
        
        Returns:
            The modular inverse of a under modulo m
        
        Raises:
            ValueError: If the modular inverse does not exist
        """
        t, new_t = 0, 1
        r, new_r = m, a

        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r

        if r > 1:
            raise ValueError(f"No modular inverse for a={a} under modulo m={m}")
        if t < 0:
            t = t + m

        return t

    def generate_key(self) -> Tuple[int, int]:
        """
        Generate a random valid key pair (a, b).
        Key requirements vary by language:
        - English: a must be coprime with 26
        - Spanish: a must be coprime with 27
        """
        a = random.choice(self.valid_a_values)
        b = random.randint(0, self.m - 1)
        return a, b

    def encrypt(self, plaintext: str, a: int, b: int) -> str:
        """
        Encrypt plaintext using the Affine cipher.
        
        Args:
            plaintext: Text to encrypt
            a: First encryption key (must be coprime with alphabet length)
            b: Second encryption key
            
        Returns:
            Encrypted text
        """
        if a not in self.valid_a_values:
            raise ValueError(f"Invalid key 'a={a}'. Must be coprime with {self.m}")
            
        ciphertext = ''
        for char in plaintext.upper():
            if char in self.alphabet:
                x = self.alphabet.index(char)
                y = (a * x + b) % self.m
                ciphertext += self.alphabet[y]
            else:
                ciphertext += char
        return ciphertext

    def decrypt(self, ciphertext: str, a: int, b: int) -> str:
        """
        Decrypt ciphertext using the Affine cipher.
        
        Args:
            ciphertext: Text to decrypt
            a: First decryption key (must be coprime with alphabet length)
            b: Second decryption key
            
        Returns:
            Decrypted text
        """
        if a not in self.valid_a_values:
            raise ValueError(f"Invalid key 'a={a}'. Must be coprime with {self.m}")
            
        a_inv = self._mod_inverse(a, self.m)  # Use the modular inverse for decryption
        plaintext = ''
        
        for char in ciphertext.upper():
            if char in self.alphabet:
                y = self.alphabet.index(char)
                x = (a_inv * (y - b)) % self.m
                plaintext += self.alphabet[x]
            else:
                plaintext += char
        return plaintext

    def save_key(self, a: int, b: int, filename: str):
        """Save the key to a file."""
        key_data = {'a': a, 'b': b}
        save_key_to_file(key_data, 'affine', filename)

    def load_key(self, filename: str) -> Tuple[int, int]:
        """Load the key from a file."""
        data = load_key_from_file(filename)
        if data['cipher_type'] != 'affine':
            raise ValueError("Invalid key file type")
        return data['key_data']['a'], data['key_data']['b']
