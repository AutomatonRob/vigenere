import argparse
import re

# Constants
# ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
DEBUG = True
BASE_SHIFT = ord('A')

def debug_print(message):
    if DEBUG:
        print(message)


def read_file(file_path):
    with open(file_path, "r") as file:
        return file.read()


def validate_string(input_name, input_string):
    # Remove all white spaces, tabs, and new lines from the string using regular expressions
    debug_print(f"Removing white space characters from {input_name}.")
    input_string_no_whitespaces = re.sub(r'\s', '', input_string)
    non_alphabetic_chars = re.search(r'[^A-Za-z]', input_string_no_whitespaces)

    # Check if string contains only characters A-Z and a-z using regular expressions
    if non_alphabetic_chars is not None:
        print(f"[ERROR] Illegal characters found in {input_name}! Only A-Z and a-z are allowed. Exiting.")
        return
    else: 
        debug_print(f"{input_name} looks OK. Processing...")
        return input_string_no_whitespaces


def string_to_upper_case_ascii_array(input_string):
    return [ord(char) for char in input_string.upper()]


def shift_enc(message_char_ascii, key_char_ascii):
    return ((message_char_ascii - BASE_SHIFT + key_char_ascii) % 26) + BASE_SHIFT


def encrypt_vigenere(message, key):
    print("Encrypting message...")
    encrypted_message_array = []
    key_length = len(key)

    message_ascii_array = string_to_upper_case_ascii_array(message)
    debug_print(f"Message ASCII-Code array: {message_ascii_array}")

    key_ascii_array = string_to_upper_case_ascii_array(key)
    debug_print(f"Key ASCII-Code array: {key_ascii_array}")

    for message_index, message_char in enumerate(message):
        key_char = key[message_index % key_length]
        encrypted_char_ascii = shift_enc(message_char, key_char)
        encrypted_message_array.append(encrypted_char_ascii)




def calculate_index_of_coincidence(secret_message):
    print("Calculate Index of Coincidence")


def main():
    parser = argparse.ArgumentParser(description="Vigenère-Cipher: Message encryption and cryptanalysis tool")
    parser.add_argument('message', type=str, help='The message you want to encrypt.')
    parser.add_argument('key', type=str, help='The key that should be used to encrypt your message.')
    args = parser.parse_args()

    message_raw = read_file(args.message)
    message = validate_string("Message", message_raw)
    debug_print(f"Original message: {message}")

    key_raw = read_file(args.key)
    key = validate_string("Key", key_raw)
    debug_print(f"Original key: {key}")

    encrypted_message = encrypt_vigenere(message, key)


if __name__ == '__main__':
    main()
