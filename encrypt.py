import os
import load_write
from decrypt import asymmetric_decrypt
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def asymmetric_encrypt(public_key, text: bytes) -> bytes:
    """Encrypts an input text using public key.

    Args:
        public_key: Public key of asymmetric encryption algorithm.
        text (bytes): Text for encryption.

    Returns:
        bytes: Encrypted text.
    """
    cipher_text = public_key.encrypt(
        text,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return cipher_text


def symmetric_encrypt(key: bytes, text: bytes) -> bytes:
    """Encrypts an input text using symmetric key.

    Args:
        key (bytes): Symmetric key of symmetric encryption algorithm.
        text (bytes): Text for encryption.

    Returns:
        bytes: Encrypted text.
    """
    padder = symmetric_padding.ANSIX923(64).padder()
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(8)
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    return iv + cipher_text


def encryption_text(settings: dict) -> None:
    """Reads the saves keys and encrypts the specified text, writing it to a new text file.

    Args:
        settings (dict): Dictionary with paths.
    """
    private_key = load_write.load_private_key(settings["secret_key"])
    cipher_key = load_write.load_symmetric_key(settings["symmetric_key"])
    symmetric_key = asymmetric_decrypt(private_key, cipher_key)
    text = load_write.read_text(settings["initial_file"])
    cipher_text = symmetric_encrypt(symmetric_key, text)
    load_write.write_text(cipher_text, settings["encrypted_file"])
