import os
import json
import logging
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa


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
        logging.info(
            f"Settings file successfully loaded from {json_file}")
    except OSError as err:
        logging.warning(
            f"Settings file wasn't loaded from {json_file}\n{err}")
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


