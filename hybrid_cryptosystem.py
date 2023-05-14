import argparse
from load_write import load_settings
from keys import create_keys
from encrypt import encryption_text
from decrypt import decryption_text


if __name__ == "__main__":
    settings = load_settings("settings.json")
    parser = argparse.ArgumentParser(description="Hybrid Cryptosystem")
    parser.add_argument("-gen", "--generation", type=int,
                        help="Запускает режим генерации ключей")
    parser.add_argument("-enc", "--encryption",
                        help="Запускает режим шифрования")
    parser.add_argument("-dec", "--decryption",
                        help="Запускает режим дешифрования")
    args = parser.parse_args()
    if args.generation:
        try:
            create_keys(args.generation, settings)
        except ValueError:
            print("Invalid key length")
        print("Keys generation completed")
    elif args.encryption:
        try:
            encryption_text(settings)
        except BaseException:
            print("Something is wrong with the encryption key")
        print("Encryption completed")
    elif args.decryption:
        try:
            decryption_text(settings)
        except BaseException:
            print("Something is wrong with the decryption key")
        print("Decryption completed")
