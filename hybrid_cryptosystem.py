import os
import json
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


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


def asymmetric_encrypt(public_key, text: bytes) -> bytes:
    """Encrypts an input text using public key.

    Args:
        public_key: Public key of asymmetric encryption algorithm.
        text (bytes): Text for encryption.

    Returns:
        bytes: Encrypted text.
    """
    cipher_text = public_key.encrypt(text, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return cipher_text
    
    
def asymmetric_decrypt(private_key, cipher_text: bytes) -> bytes:
    """Decrypts an asymmetrical ciphertext using private key.

    Args:
        private_key: Private key of asymmetric encryption algorithm.
        cipher_text (bytes): Encrypted text.
            
    Returns:
        bytes: Decrypted text.
    """
    text = private_key.decrypt(cipher_text, asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return text


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


def symmetric_decrypt(key: bytes, cipher_text: bytes) -> bytes:
    """Decrypts a symmetrical ciphertext using symmetric key.

    Args:
        key (bytes): Symmetric key of symmetric encryption algorithm.
        cipher_text (bytes): Encrypted text.

    Returns:
        bytes: Decrypted text.
    """
    cipher_text, iv = cipher_text[8:], cipher_text[:8]
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = symmetric_padding.ANSIX923(64).unpadder()
    unpadded_text = unpadder.update(text) + unpadder.finalize() 
    return unpadded_text


def read_text(file_name: str) -> bytes:
    """Reads text from txt file.

    Args:
        file_name (str): Name of txt file.

    Returns:
        bytes: Text in byte form.
    """
    try:
        with open(file_name, mode='rb') as text_file:
            text = text_file.read()
    except OSError as err:
        raise err
    return text


def write_text(text: bytes, file_name: str) -> None:
    """Writes text to txt file.

    Args:
        text (bytes): Text for writing.
        file_name (str): Name of txt file.
    """
    try:
        with open(file_name, mode='wb') as text_file:
            text_file.write(text)
    except OSError as err:
        raise err


def load_symmetric_key(file_name: str) -> bytes:
    """Loads a symmetric key from txt file.

    Args:
        file_name (str): Name of txt file.

    Returns:
        bytes: Symmetric key for symmetric encoding algorithm.
    """
    try:
        with open(file_name, mode='rb') as key_file:
            key = key_file.read()
    except OSError as err:
        raise err
    return key


def load_private_key(private_pem: str):
    """Loads a private key from pem file.

    Args:
        private_pem (str): Name of pem file.

    Returns:
        Private key for asymmetric encoding algorithm.
    """
    private_key = None
    try:
        with open(private_pem, 'rb') as pem_in:
            private_bytes = pem_in.read()
        private_key = load_pem_private_key(private_bytes, password=None)
    except OSError as err:
        raise err
    return private_key


def load_public_key(public_pem: str):
    """Loads a public key from pem file.

    Args:
        public_pem (str): Name of pem file.

    Returns:
        Public key for asymmetric encoding algorithm.
    """
    public_key = None
    try:
        with open(public_pem, 'rb') as pem_in:
            public_bytes = pem_in.read()
        public_key = load_pem_public_key(public_bytes)
    except OSError as err:
        raise err
    return public_key

def create_and_save_keys(length: int, settings: dict) -> None:
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
        save_public_key(public_key, settings['public_key'])
        save_private_key(private_key, settings['secret_key'])
        ciphered_key = asymmetric_encrypt(public_key, symmetric_key)
        save_symmetric_key(ciphered_key, settings['symmetric_key'])
    else:
        raise ValueError 
    
def encryption_text(settings: dict) -> None:
    """Reads the saves keys and encrypts the specified text, writing it to a new text file.
    
    Args: 
        settings (dict): Dictionary with paths.
    """
    private_key = load_private_key(settings['secret_key'])
    cipher_key = load_symmetric_key(settings['symmetric_key'])
    symmetric_key = asymmetric_decrypt(private_key, cipher_key)
    text =  read_text(settings['initial_file'])
    cipher_text = symmetric_encrypt(symmetric_key,text)
    write_text(cipher_text, settings['encrypted_file'])
      
    
def decryption_text(settings: dict)->None:
    """Reads an encrypts text file and decrypts the text using keys, saving it to a new file.

    Args: 
        settings (dict): Dictionary with paths.
    """
    private_key = load_private_key(settings['secret_key'])
    cipher_key = load_symmetric_key(settings['symmetric_key'])
    symmetric_key = asymmetric_decrypt(private_key, cipher_key)
    cipher_text = read_text(settings['encrypted_file'])
    text = symmetric_decrypt(symmetric_key, cipher_text)
    write_text(text, settings['decrypted_file'])


if __name__ == "__main__":
    settings = load_settings("settings.json")
    parser = argparse.ArgumentParser(description='Hybrid Cryptosystem')
    parser.add_argument('-gen','--generation', help='Запускает режим генерации ключей')   
    parser.add_argument('-enc','--encryption', help='Запускает режим шифрования')
    parser.add_argument('-dec','--decryption', help='Запускает режим дешифрования')
    args = parser.parse_args()
    if args.generation:
        try:
            create_and_save_keys(args.generation, settings)
        except ValueError:
            print("Invalid key length")
        print("Keys generation completed")
    elif args.encryption:
        try:
            encryption_text(settings)
        except BaseException:
            print("Something is wrong with the encryption key")
        print("Encryption completed")
    else:
        try:
            decryption_text(settings)
        except BaseException:
            print("Something is wrong with the decryption key")
        print("Decryption completed")
        