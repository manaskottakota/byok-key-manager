import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
from crypto import generate_key, encrypt_key_for_storage

from typing import Optional, Dict, Any


KEYS_FILE = "data/keys.json"
MASTER_KEY = b'?????????' # CHOOOSE SOME MASTER KEY


def _load_keys() -> Dict[str, Any]:
    """load keys from storage"""
    if not os.path.exists(KEYS_FILE): # file not found
        return {}
    with open(KEYS_FILE, 'r') as file: 
        return json.load(file)              # return organized key data
    

def _save_keys(keys: Dict[str, Any]) -> None:
    """save keys to storage"""
    os.makedirs("data", exist_ok = True)

    with open (KEYS_FILE, 'w') as file:
        json.dump(keys, file, indent = 2)


def create_key(key_id: str) -> None: 
    """generate new key and save encrypted to storage"""
    
    keys = _load_keys()

    if key_id in keys and not keys[key_id].get('revoked', False):       # key_id exists and hasn't been revoked
        raise ValueError(f"Key {key_id} already exists")
    
    new_key = generate_key()
    encrypted_key = encrypt_key_for_storage(new_key, MASTER_KEY)

    keys[key_id] = {"version": 1, "encrypted_key": encrypted_key.decode('utf-8'),  # json format
                    "created": datetime.now().isoformat(), "revoked": False}

    _save_keys(keys) # save to storage



def get_key(key_id: str) -> bytes:
    """load and decrypt key from storage"""
    from crypto import decrypt_data

    keys = _load_keys()

    if key_id not in keys:
        raise ValueError(f"Key {key_id} not found")
    
    if keys[key_id]['revoked']:
        raise ValueError(f"Key {key_id} is revoked")
    
    encrypted_key = keys[key_id]['encrypted_key'].encode('utf-8')
    
    from cryptography.fernet import Fernet
    f = Fernet(MASTER_KEY)
    return f.decrypt(encrypted_key)


def rotate_key(key_id: str) -> None:
    """create new version of a key and increment the version number"""
    keys = _load_keys()

    if key_id not in keys:
        raise ValueError(f"Key {key_id} not found")
    
    old_version = keys[key_id]['version']
    new_key = generate_key()
    encrypted_key = encrypt_key_for_storage(new_key, MASTER_KEY)

    keys[key_id] = {"version": old_version + 1, "encrypted_key": encrypted_key.decode('utf-8'),
                    "created": datetime.now().isoformat(), "revoked": False}


def revoke_key(key_id: str) -> None:
    """mark a key as disabled"""
    
    keys = _load_keys()

    if key_id not in keys:
        raise ValueError(f"Key {key_id} not found")
    
    keys[key_id]['revoked'] = True

    _save_keys(keys)