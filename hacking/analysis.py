from collections import Counter
from typing import List, Tuple, Dict
import string

class TextAnalysis:
    """Text analysis tools for cryptanalysis with support for English and Spanish."""
    
    def __init__(self, language: str = 'en'):
        """
        Initialize text analysis tools.
        
        Args:
            language: Language code ('en' for English or 'es' for Spanish)
        """
        # Define alphabets for both languages
        self.alphabets = {
            'en': string.ascii_uppercase,  # 26 letters
            'es': "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"  # 27 letters
        }
        self.alphabet = self.alphabets.get(language, self.alphabets['en'])
        self.language = language
        
        # Letter frequencies for both languages (in percentage)
        self.letter_frequencies = {
            'en': {
                'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 
                'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
                'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
                'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
                'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
                'Z': 0.07
            },
            'es': {
                'E': 13.68, 'A': 12.53, 'O': 8.68, 'S': 7.98, 'R': 6.87, 
                'N': 6.71, 'I': 6.25, 'D': 5.86, 'L': 4.97, 'C': 4.68,
                'T': 4.63, 'U': 3.93, 'M': 3.15, 'P': 2.51, 'B': 1.42,
                'G': 1.01, 'V': 0.90, 'Y': 0.90, 'Q': 0.88, 'H': 0.70,
                'F': 0.69, 'Z': 0.52, 'J': 0.44, 'Ñ': 0.31, 'X': 0.22,
                'W': 0.02, 'K': 0.01
            }
        }
        
        # Common bigrams by language
        self.common_bigrams = {
            'en': ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND'],
            'es': ['ES', 'DE', 'EN', 'EL', 'LA', 'QU', 'UE', 'ER', 'RA', 'RE']
        }
        
        # Common trigrams by language
        self.common_trigrams = {
            'en': ['THE', 'AND', 'ING', 'ENT', 'ION', 'HER', 'FOR', 'THA', 'NTH', 'INT'],
            'es': ['QUE', 'EST', 'ADO', 'PAR', 'LOS', 'RES', 'ESE', 'TRA', 'CON', 'ENT']
        }

    def analyze_frequency(self, text: str) -> List[Tuple[str, float]]:
        """
        Perform frequency analysis on the text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of (character, frequency percentage) pairs
        """
        # Clean and convert text
        clean_text = ''.join(c for c in text.upper() if c in self.alphabet)
        if not clean_text:
            return []
            
        # Count frequencies
        total = len(clean_text)
        frequencies = Counter(clean_text)
        
        # Convert to percentages and sort by frequency
        freq_list = [(char, (count/total) * 100) for char, count in frequencies.items()]
        return sorted(freq_list, key=lambda x: x[1], reverse=True)

    def analyze_ngrams(self, text: str, n: int) -> List[Tuple[str, int]]:
        """
        Analyze n-gram frequencies in text.
        
        Args:
            text: Text to analyze
            n: Length of n-grams
        """
        # Clean text
        clean_text = ''.join(c for c in text.upper() if c in self.alphabet)
        if len(clean_text) < n:
            return []
            
        # Get all n-grams
        ngrams = [''.join(gram) for gram in zip(*[clean_text[i:] for i in range(n)])]
        return Counter(ngrams).most_common()

    def index_of_coincidence(self, text: str) -> float:
        """
        Calculate Index of Coincidence for text.
        
        Args:
            text: Text to analyze
        """
        clean_text = ''.join(c for c in text.upper() if c in self.alphabet)
        N = len(clean_text)
        if N <= 1:
            return 0.0
            
        # Count frequencies
        freqs = Counter(clean_text)
        
        # Calculate IoC
        sum_freqs = sum(f * (f - 1) for f in freqs.values())
        ioc = sum_freqs / (N * (N - 1))
        return ioc

    def get_likely_key_lengths(self, text: str, max_length: int = 20) -> List[Tuple[int, float]]:
        """
        Find possible key lengths using IoC for Polyalphabetic cipher.
        
        Args:
            text: Encrypted text
            max_length: Maximum key length to consider
            
        Returns:
            List of (length, score) tuples sorted by likelihood
        """
        clean_text = ''.join(c for c in text.upper() if c in self.alphabet)
        results = []
        
        # Try different key lengths
        for length in range(1, min(max_length + 1, len(clean_text))):
            # Split text into columns
            columns = [''.join(clean_text[i::length]) for i in range(length)]
            
            # Calculate average IoC for this key length
            avg_ioc = sum(self.index_of_coincidence(col) for col in columns) / length
            results.append((length, avg_ioc))
        
        # Sort by IoC value (higher is better)
        return sorted(results, key=lambda x: x[1], reverse=True)

    def frequency_score(self, text: str) -> float:
        """
        Calculate a frequency score based on letter frequency distributions.
        
        Args:
            text: Text to score
            
        Returns:
            Score representing how closely the text matches expected frequencies.
        """
        clean_text = ''.join(c for c in text.upper() if c in self.alphabet)
        total = len(clean_text)
        if total == 0:
            return 0.0

        # Get frequencies
        frequencies = Counter(clean_text)
        score = 0.0

        for char, expected_freq in self.letter_frequencies[self.language].items():
            actual_freq = (frequencies[char] / total) * 100 if char in frequencies else 0
            # Calculate score based on difference between actual and expected frequency
            score += max(0, 100 - abs(expected_freq - actual_freq))

        return score / len(self.alphabet)

    def ngram_score(self, text: str, n: int) -> float:
        """
        Calculate an n-gram score for the text.
        
        Args:
            text: Text to score
            n: Length of the n-gram (2 for bigram, 3 for trigram, etc.)
            
        Returns:
            Score representing how closely the n-gram matches expected distributions.
        """
        ngrams = self.analyze_ngrams(text, n)
        expected_ngrams = self.common_bigrams if n == 2 else self.common_trigrams

        score = 0.0
        for ngram, count in ngrams:
            if ngram in expected_ngrams[self.language]:
                score += count  # Increase score for common n-grams

        return score

    def word_score(self, text: str) -> float:
        """
        Score the text based on common word occurrences.
        
        Args:
            text: Text to score
            
        Returns:
            Score based on how many common words are present in the text.
        """
        common_words = {
            'en': ['THE', 'AND', 'TO', 'OF', 'A', 'IN', 'IS', 'IT', 'YOU', 'THAT'],
            'es': ['QUE', 'DE', 'LA', 'EL', 'EN', 'Y', 'A', 'LOS', 'DEL', 'SE']
        }
        words = text.upper().split()
        score = sum(1 for word in words if word in common_words[self.language])
        return score / len(words) if words else 0.0
