import argparse
import logging
from load_write import load_settings
from keys import create_keys
from encrypt import encryption_text
from decrypt import decryption_text


if __name__ == "__main__":
    settings = load_settings("settings.json")
    parser = argparse.ArgumentParser(description="Hybrid Cryptosystem")
    parser.add_argument(
        "-gen", "--generation", type=int, help="Запускает режим генерации ключей"
    )
    parser.add_argument("-enc", "--encryption", help="Запускает режим шифрования")
    parser.add_argument("-dec", "--decryption", help="Запускает режим дешифрования")
    args = parser.parse_args()
    if args.generation:
        try:
            create_keys(args.generation, settings)
            logging.info("Keys generation completed")
        except ValueError:
            logging.info(
                "Invalid key length: the key length should be from 40 to 128 in 8-bit increments."
            )
    elif args.encryption:
        try:
            encryption_text(settings)
            logging.info("Encryption completed")
        except BaseException:
            logging.info("Something is wrong with the encryption key")
    elif args.decryption:
        try:
            decryption_text(settings)
            logging.info("Decryption completed")
        except BaseException:
            logging.info("Something is wrong with the decryption key")
