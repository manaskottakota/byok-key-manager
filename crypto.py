import os
from cryptography.fernet import Fernet


def generate_key() -> bytes:
    """create a randomized 256 bit key for encryption"""
    key: bytes = Fernet.generate_key()   # 32 bytes will be 256 bits - enough for security strength -> storable format
    return key


def encrypt_data(key: bytes, plaintext: str) -> bytes:
    """encrypt plaintext (arg) data using a valid key (arg) -> encrypted ciphertext in bytes"""
    fkey = Fernet(key) # intialize an encryption engine using the key (arg)
    plaintext_bytes: bytes = plaintext.encode('utf-8') # convert string to bytes
    ciphertext: bytes = fkey.encrypt(plaintext_bytes)
    return ciphertext


def decrypt_data(key: bytes, ciphertext: bytes) -> str:
    """decrypt ciphertext (arg) data using a valid key (arg) -> decrypted plaintext"""
    fkey = Fernet(key)
    plaintext_bytes: bytes = fkey.decrypt(ciphertext)
    plaintext: str = plaintext_bytes.decode('utf-8')
    return plaintext

def encrypt_key_for_storage(key: bytes, master_key: bytes) -> bytes:
    """encrypt a key (arg) using a master key(arg) for secure storage"""
    fkey = Fernet(master_key)
    encrypted_key: bytes = fkey.encrypt(key)
    return encrypted_key
