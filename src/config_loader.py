import json


CONFIG_FILE = "config/config.json"


def load_config():
    """
    Load the analyzer configuration from config/config.json.
    """

    with open(
        CONFIG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)
