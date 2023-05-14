import os
import json
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def load_settings(json_file: str) -> dict:
    """Loads a settings file into the program.

    Args:
        json_file (str): The path to the json file with the settings.

    Returns:
        dict: dictionary with settings
    """
    settings = None
    try:
        with open(json_file) as json_file:
            settings = json.load(json_file)
    except OSError as err:
       raise err
    return settings


def generate_symmetric_key(length: int) -> bytes:
    """Generates a symmetric key for symmetric encryption algorithm.

    Args:
        length (int): Key length in bytes.

    Returns:
        bytes: Symmetric key.
    """
    symmetric_key = os.urandom(length)
    return symmetric_key


def generate_asymmetric_keys() -> tuple:
    """Generates an asymmetric key for asymmetric encryption algorithm.

    Returns:
        tuple: Asymmetric keys.
    """
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    return private_key, public_key


def save_symmetric_key(key: bytes, file_name: str) -> None:
    """Saves a symmetric key to txt file.

    Args:
        key (bytes): Symmetric key.
        file_name (str): Name of txt file.
    """
    try:
        with open(file_name, 'wb') as key_file:
            key_file.write(key)
    except OSError as err:
        raise err
    
    
def save_private_key(private_key, file_name: str) -> None:
    """Saves a private key to pem file.

    Args:
        private_key: Private key for asymmetric encoding algorithm.
        file_name (str): Pem file for private key.
     """
    try:
        with open(file_name, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
    except OSError as err:
        raise err
        
        
def save_public_key(public_key, file_name:str)->None:
    """Saves a public key to pem file.

    Args:
        public_key: Public key for asymmetric encoding algorithm.
        file_name (str): Pem file for public key.
    """
    try:
        with open(file_name, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    except OSError as err:
        raise err