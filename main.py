import argparse
import sys
from typing import Any, Dict
from ciphers.affine_cipher import AffineCipher
from ciphers.monoalphabetic_cipher import MonoalphabeticCipher
from ciphers.polyalphabetic_cipher import PolyalphabeticCipher
from ciphers.des_cipher import DESCipher
from hacking.brute_force import BruteForce
from hacking.analysis import TextAnalysis
from utils.file_io import save_text_to_file, load_text_from_file

class CryptoSystem:
    
    def __init__(self, language: str = 'en'):
        self.affine = AffineCipher(language)
        self.mono = MonoalphabeticCipher(language)
        self.poly = PolyalphabeticCipher(language)
        self.des = DESCipher()
        self.brute_force = BruteForce(language)
        self.analysis = TextAnalysis(language)

    def get_cipher_instance(self, cipher_type: str):
        ciphers = {
            'affine': self.affine,
            'mono': self.mono,
            'poly': self.poly,
            'des': self.des
        }
        return ciphers.get(cipher_type)


    def encrypt_text(self, cipher_type: str, text: str, key: Any) -> str:
        if cipher_type == 'affine':
            return self.affine.encrypt(text, key[0], key[1])
        elif cipher_type == 'mono':
            self.mono.set_key(key)
            return self.mono.encrypt(text)
        elif cipher_type == 'poly':
            return self.poly.encrypt(text, key)
        elif cipher_type == 'des':
            return self.des.encrypt(text, key).hex()
        else:
            raise ValueError("Unknown cipher type:")

    def decrypt_text(self, cipher_type: str, text: str, key: Any) -> str:
        if cipher_type == 'affine':
            return self.affine.decrypt(text, key[0], key[1])
        elif cipher_type == 'mono':
            return self.mono.decrypt(text)
        elif cipher_type == 'poly':
            return self.poly.decrypt(text, key)
        elif cipher_type == 'des':
            return self.des.decrypt(bytes.fromhex(text), key)
        else:
            raise ValueError("Unknown cipher type:")

    # def crack_cipher(self, cipher_type: str, text: str) -> list[tuple[Any, str, float]]:
    #     """Attempt to crack the cipher."""
    #     if cipher_type == 'affine':
    #         return self.brute_force.crack_affine(text)
    #     elif cipher_type == 'mono':
    #         freq_analysis = self.mono.analyze_frequency(text)
    #         return [('Frequency Analysis:', freq_analysis, 0.0)]
    #     elif cipher_type == 'poly':
    #         key_analysis = self.poly.analyze_key_length(text)
    #         possible_keys = self.brute_force.crack_polyalphabetic(text)
    #         return possible_keys
    #     else:
    #         raise ValueError(f"Cracking not implemented for cipher type: {cipher_type}")

def main():
    parser = argparse.ArgumentParser(description='Cryptographic Systems Implementation')
    parser.add_argument('operation', choices=['encrypt', 'decrypt', 'crack'])
    parser.add_argument('cipher', choices=['affine', 'mono', 'poly', 'des'])
    parser.add_argument('--input', '-i', required=True)
    parser.add_argument('--output', '-o')
    parser.add_argument('--key', '-k')
    parser.add_argument('--language', '-l', choices=['en', 'es'], default='en')
    args = parser.parse_args()
    
    crypto = CryptoSystem(args.language)

    try:
        if args.input.endswith('.txt'):
            text = load_text_from_file(args.input)
        else:
            text = args.input
    except Exception as e:
        print(f"Error loading input: {e}")
        sys.exit(1)

    try:
        if args.operation in ['encrypt', 'decrypt']:
            if not args.key:
                if args.operation == 'encrypt':
                    if args.cipher == 'affine':
                        key = crypto.affine.generate_key()
                        if args.output:
                            crypto.affine.save_key(key[0], key[1], 'data/affine/affine_key.json')
                    elif args.cipher == 'mono':
                        key = crypto.mono.generate_key()
                        if args.output:
                            crypto.mono.save_key('data/mono/mono_key.json')
                    elif args.cipher == 'poly':
                        key = crypto.poly.generate_key(5)
                        if args.output:
                            crypto.poly.save_key(key, 'data/poly/poly_key.json')
                    elif args.cipher == 'des':
                        key = crypto.des.generate_key()
                        if args.output:
                            crypto.des.save_key(key, 'data/des/des_key.json')
                else:
                    print("Key is required for decryption")
                    sys.exit(1)
            else:
                if args.cipher == 'affine':
                    key = crypto.affine.load_key(args.key)
                elif args.cipher == 'mono':
                    print(args.key)
                    key = crypto.mono.load_key(args.key)
                elif args.cipher == 'poly':
                    key = crypto.poly.load_key(args.key)
                elif args.cipher == 'des':
                    key = crypto.des.load_key(args.key)

            if args.operation == 'encrypt':
                result = crypto.encrypt_text(args.cipher, text, key)
            else:
                result = crypto.decrypt_text(args.cipher, text, key)

        # else:  # crack
        #     results = crypto.crack_cipher(args.cipher, text)
        #     if args.cipher == 'mono':
        #         print("\nFrequency Analysis Results:")
        #         for char, freq in results[0][1].items():
        #             print(f"{char}: {freq:.2f}%")
        #     else:
        #         print("\nPossible decryptions:")
        #         for key, text, score in results[:5]:
        #             print(f"\nScore: {score:.2f}")
        #             print(f"Key: {key}")
        #             print(f"Text: {text}")
        #     return

        # Save or print result
        if args.output:
            save_text_to_file(result, args.output)
            print(f"Result saved to {args.output}")
        else:
            print("\nResult:")
            print(result)

    except Exception as e:
        print(f"Error during operation: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()