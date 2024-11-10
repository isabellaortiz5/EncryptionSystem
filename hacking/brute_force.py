from typing import List, Tuple, Dict
from collections import Counter
import string
import itertools
from ciphers.affine_cipher import AffineCipher
from ciphers.polyalphabetic_cipher import PolyalphabeticCipher
from hacking.analysis import TextAnalysis

class BruteForce:
    """Implementation of brute force attacks for various ciphers."""
    
    def __init__(self, language: str = 'en'):
        """
        Initialize brute force attack tools.
        
        Args:
            language: Language for frequency analysis ('en' or 'de')
        """
        self.analysis = TextAnalysis(language)
        
        # Language-specific letter frequencies
        self.freq_maps = {
            'en': 'ETAOINSHRDLCUMWFGYPBVKJXQZ',
            'de': 'ENISRATDHULCGMOBWFKZPVJYXQ'
        }
        self.language = language

    def crack_affine(self, ciphertext: str, top_n: int = 5) -> List[Tuple[Dict[str, int], str, float]]:
        """
        Attempt to crack Affine cipher using brute force.
        
        Args:
            ciphertext: Encrypted text to crack
            top_n: Number of best results to return
            
        Returns:
            List of (key, decrypted_text, score) tuples sorted by likelihood
        """
        cipher = AffineCipher()
        results = []
        
        # Try all possible combinations of a and b
        for a in cipher.valid_a_values:
            for b in range(26):
                try:
                    decrypted = cipher.decrypt(ciphertext, a, b)
                    score = self._score_text(decrypted)
                    results.append(({'a': a, 'b': b}, decrypted, score))
                except ValueError:
                    continue
                    
        top_n = min(top_n, len(results))
        return sorted(results, key=lambda x: x[2], reverse=True)[:top_n]

    def crack_polyalphabetic(self, ciphertext: str, max_key_length: int = 10) -> List[Tuple[str, str, float]]:
        """
        Attempt to crack Polyalphabetic cipher using frequency analysis and brute force.
        
        Args:
            ciphertext: Encrypted text to crack
            max_key_length: Maximum key length to try
            
        Returns:
            List of (key, decrypted_text, score) tuples sorted by likelihood
        """
        cipher = PolyalphabeticCipher()
        results = []
        
        # First, try to determine the key length using Index of Coincidence
        likely_lengths = self.analysis.get_likely_key_lengths(ciphertext)
        
        # Try the most promising key lengths
        for key_length, _ in likely_lengths[:3]:
            # Split text into columns based on key length
            columns = [''.join(ciphertext[i::key_length]) for i in range(key_length)]
            
            # Analyze each column
            key = ''
            for col in columns:
                # Get frequency analysis for this column
                freq = Counter(col)
                most_common = sorted(freq.items(), key=lambda x: x[1], reverse=True)
                
                # Try the most likely shifts based on expected frequency
                for expected in self.freq_maps[self.language][:5]:
                    actual = most_common[0][0] if most_common else 'A'
                    shift = (ord(actual) - ord(expected)) % 26
                    key += chr((26 - shift) % 26 + ord('A'))
            
            # Try the potential key
            decrypted = cipher.decrypt(ciphertext, key)
            score = self._score_text(decrypted)
            results.append((key, decrypted, score))
        
        return sorted(results, key=lambda x: x[2], reverse=True)

    def _score_text(self, text: str, freq_weight: float = 0.4, bigram_weight: float = 0.2, trigram_weight: float = 0.2, word_weight: float = 0.2) -> float:
        """
        Score text based on language characteristics.
        
        Args:
            text: Text to score
            freq_weight: Weight for frequency score
            bigram_weight: Weight for bigram score
            trigram_weight: Weight for trigram score
            word_weight: Weight for word score
            
        Returns:
            Float score (higher is more likely to be correct plaintext)
        """
        # Get character frequency score
        freq_score = self.analysis.frequency_score(text)
        
        # Get n-gram score
        bigram_score = self.analysis.ngram_score(text, 2)
        trigram_score = self.analysis.ngram_score(text, 3)
        
        # Check for common words
        word_score = self.analysis.word_score(text)
        
        # Combine scores with weights
        return freq_score * freq_weight + bigram_score * bigram_weight + trigram_score * trigram_weight + word_score * word_weight
