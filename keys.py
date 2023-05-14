import os
import load_write
from encrypt import asymmetric_encrypt
from cryptography.hazmat.primitives.asymmetric import rsa


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


def create_keys(length: int, settings: dict) -> None:
    """Generates symmetric, public and private keys, 
    stores them in the specified paths and decrypts the symmetric key using the public key.

    Args:
        length (int): Symmetric key length.
        settings (dict): Dictionary with paths.
    """
    if length > 39 and length < 129 and length % 8 == 0:
        length = int(length/8)
        symmetric_key = generate_symmetric_key(length)
        private_key, public_key = generate_asymmetric_keys()
        load_write.save_public_key(public_key, settings['public_key'])
        load_write.save_private_key(private_key, settings['secret_key'])
        ciphered_key = asymmetric_encrypt(public_key, symmetric_key)
        load_write.save_symmetric_key(ciphered_key, settings['symmetric_key'])
    else:
        raise ValueError
