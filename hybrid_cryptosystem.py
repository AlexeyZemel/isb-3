import json
import logging
import argparse


def load_settings(json_file: str) -> dict:
    """Loads a configuration file into the program

    Args:
        json_file (str): The path to the json file with the settings.
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


