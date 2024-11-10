import json
from typing import Dict, Any
import os

import os
import json
from typing import Dict, Any

def save_key_to_file(key_data: Dict[str, Any], cipher_type: str, filename: str) -> None:
    """
    Save encryption/decryption key data to a JSON file.

    Args:
        key_data: Dictionary containing key information
        cipher_type: Type of cipher (affine, monoalphabetic, etc.)
        filename: Name of file to save to
    """
    data = {
        'cipher_type': cipher_type,
        'key_data': key_data
    }

    # Extract directory from filename
    directory = os.path.dirname(filename)

    # Create directory if it doesn't exist and if the directory is not empty
    if directory:
        os.makedirs(directory, exist_ok=True)

    # Write data to JSON file
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print("Key file successfully created.")
    except Exception as e:
        print(f"Failed to save the key file: {e}")


def load_key_from_file(filename: str) -> Dict[str, Any]:
    """
    Load encryption/decryption key data from a JSON file.
    
    Args:
        filename: Name of file to load from
        
    Returns:
        Dictionary containing the loaded key data
    """
    with open(filename, 'r') as f:
        data = json.load(f)
    return data

def save_text_to_file(text: str, filename: str) -> None:
    """
    Save text to a file.
    
    Args:
        text: Text to save
        filename: Name of file to save to
    """
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        f.write(text)

def load_text_from_file(filename: str) -> str:
    """
    Load text from a file.
    
    Args:
        filename: Name of file to load from
        
    Returns:
        Content of the file as string
    """
    with open(filename, 'r') as f:
        return f.read()