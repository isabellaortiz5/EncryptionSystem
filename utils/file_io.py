import json
from typing import Dict, Any
import os

import os
import json
from typing import Dict, Any

def save_key_to_file(key_data: Dict[str, Any], cipher_type: str, filename: str) -> None:
    data = {
        'cipher_type': cipher_type,
        'key_data': key_data
    }

    directory = os.path.dirname(filename)
    if directory:
        os.makedirs(directory, exist_ok=True)

    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print("Key file successfully created.")
    except Exception as e:
        print(f"Failed to save the key file: {e}")


def load_key_from_file(filename: str) -> Dict[str, Any]:
    with open(filename, 'r') as f:
        data = json.load(f)
    return data

def save_text_to_file(text: str, filename: str) -> None:
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        f.write(text)

def load_text_from_file(filename: str) -> str:
    with open(filename, 'r') as f:
        return f.read()