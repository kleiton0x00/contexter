# utils.py

import requests
from color_codes import COLORS, reset

def print_msg(message_type, message):
    if message_type in COLORS:
        color_code, symbol = COLORS[message_type]
        print(f"{color_code}{symbol}{reset} {message}")
    else:
        print(message)  # Default to printing without color if the message type is not recognized

def disable_warnings():
    # Disable warnings
    requests.packages.urllib3.disable_warnings()
