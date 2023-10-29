import argparse
import re

# Constants
# ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
DEBUG = True

def debug_print(message):
    if DEBUG:
        print(message)

def read_file(file_path):
    with open(file_path, "r") as file:
        return file.read()
    
def validate_string(input_name, input_string):
    # Remove all white spaces, tabs, and new lines from the string using regular expressions
    debug_print("Removing white space characters from " + input_name)
    input_string_no_whitespaces = re.sub(r'\s', '', input_string)
    non_alphabetic_chars = re.search(r'[^A-Za-z]', input_string_no_whitespaces)

    # Check if string contains only characters A-Z and a-z using regular expressions
    if non_alphabetic_chars is not None:
        print("[ERROR] Illegal characters found in " + input_name + "! Only A-Z and a-z are allowed. Exiting.")
        return
    else: 
        debug_print(input_name + " looks OK. Processing...")
        return input_string_no_whitespaces

def encrypt_vigenere(message, key):
    print("Encrypting message...")


def main():
    parser = argparse.ArgumentParser(description="Vigenère-Cipher: Message encryption and cryptanalysis tool")
    parser.add_argument('message', type=str, help='The message you want to encrypt.')
    parser.add_argument('key', type=str, help='The key that should be used to encrypt your message.')
    args = parser.parse_args()

    message_raw = read_file(args.message)
    message = validate_string("Message", message_raw)
    debug_print(message)

    key_raw = read_file(args.key)
    key = validate_string("Key", key_raw)
    debug_print(key)


    # Import Message

    # Check if message only contains characters from Latin alphabet, otherwise return error message and stop

    # Import Key

    # Check if key only contains characters from Latin alphabet, otherwise return error message and stop

    # Prepare Message and remove white space

    # 


if __name__ == '__main__':
    main()
