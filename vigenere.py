### IMPORTS
import argparse
import re

### CONSTANTS
#ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DEBUG = True
MODES = ["e", "encrypt", "d", "decrypt", "a", "analyse"]
BASE_SHIFT = ord("A")
ALPHABET_LENGTH = 26
OUTPUT_ENCRYPTED_FILE_NAME = "vigenere_message_encrypted.txt"
OUTPUT_DECRYPTED_FILE_NAME = "vigenere_message_decrypted.txt"
OUTPUT_ANALYZED_FILE_NAME = "vigenere_message_analyzed.txt"


def debug_print(message):
    if DEBUG:
        print(f"[DEBUG] {message}")


def read_file(file_path):
    with open(file_path, "r") as file:
        return file.read()


def validate_string(input_name, input_string):
    ### Remove all white spaces, tabs, and new lines from the string using regular expressions
    debug_print(f"Removing white space characters from {input_name}.")
    input_string_no_whitespaces = re.sub(r"\s", "", input_string)
    non_alphabetic_chars = re.search(r"[^A-Za-z]", input_string_no_whitespaces)

    ### Check if string contains only characters A-Z and a-z using regular expressions
    if non_alphabetic_chars is not None:
        print(f"[ERROR] Illegal characters found in {input_name}! Only A-Z and a-z are allowed. Exiting.")
        return
    else: 
        debug_print(f"{input_name} looks OK. Processing...")
        return input_string_no_whitespaces


def string_to_upper_case_ascii_array(input_string):
    return [ord(char) for char in input_string.upper()]


def shift_enc(message_char_ascii, key_char_ascii):
    return (((message_char_ascii - BASE_SHIFT) + (key_char_ascii - BASE_SHIFT)) % 26) + BASE_SHIFT


def shift_dec(message_encrypted_char_ascii, key_char_ascii):
    return abs((message_encrypted_char_ascii - BASE_SHIFT) - (key_char_ascii - BASE_SHIFT)) % 26 + BASE_SHIFT

    return 1

def ascii_array_to_string(ascii_array):
    return "".join(chr(ascii_code) for ascii_code in ascii_array)


def process_input_file(file_name, file_type):
    string_raw = read_file(file_name)
    string = validate_string(file_type, string_raw)
    
    debug_print(f"Original {file_type}: {string}")
    
    return string


def encrypt_vigenere(message_file_name, key_file_name):
    encrypted_message_array = []
    
    debug_print("Loading message and key file...")
    message = process_input_file(message_file_name, "Message")
    key = process_input_file(key_file_name, "Key")

    print("[INFO] Encrypting message...")

    message_ascii_array = string_to_upper_case_ascii_array(message)
    debug_print(f"Message ASCII-Code array: {message_ascii_array}")

    key_ascii_array = string_to_upper_case_ascii_array(key)
    debug_print(f"Key ASCII-Code array: {key_ascii_array}")
    key_ascii_array_length = len(key_ascii_array)

    for msg_index, message_char_ascii in enumerate(message_ascii_array):
        key_char_ascii = key_ascii_array[msg_index % key_ascii_array_length]
        encrypted_char_ascii = shift_enc(message_char_ascii, key_char_ascii)
        encrypted_message_array.append(encrypted_char_ascii)

    debug_print(f"Encrypted message (ASCII-Code): {encrypted_message_array}")
    
    encrypted_message_string = ascii_array_to_string(encrypted_message_array)
    debug_print(f"Encrypted message (string): {encrypted_message_string}")
    
    write_string_to_file(OUTPUT_ENCRYPTED_FILE_NAME, encrypted_message_string)

    print(f"[INFO] DONE! Encrypted message saved in: {OUTPUT_ENCRYPTED_FILE_NAME}")


def decrypt_vigenere(encrypted_message_file_name, key_file_name):
    decrypted_message_array = []
    
    debug_print("Loading encrypted message and key file...")
    message_encrypted = process_input_file(encrypted_message_file_name, "Encrypted message")
    key = process_input_file(key_file_name, "Key")

    print("[INFO] Decrypting message...")

    message_encrypted_ascii_array = string_to_upper_case_ascii_array(message_encrypted)
    debug_print(f"Encrypted message ASCII-Code array: {message_encrypted_ascii_array}")

    key_ascii_array = string_to_upper_case_ascii_array(key)
    debug_print(f"Key ASCII-Code array: {key_ascii_array}")
    key_ascii_array_length = len(key_ascii_array)

    for msg_enc_index, msg_enc_char_ascii in enumerate(message_encrypted_ascii_array):
        key_char_ascii = key_ascii_array[msg_enc_index % key_ascii_array_length]
        decrypted_char_ascii = shift_dec(msg_enc_char_ascii, key_char_ascii)
        decrypted_message_array.append(decrypted_char_ascii)
    
    debug_print(f"Decrypted message (ASCII-Code): {decrypted_message_array}")

    decrypted_message_string = ascii_array_to_string(decrypted_message_array)
    debug_print(f"Decrypted message (string): {decrypted_message_string}")
    
    write_string_to_file(OUTPUT_DECRYPTED_FILE_NAME, decrypted_message_string)

    print(f"[INFO] DONE! Decrypted message saved in: {OUTPUT_DECRYPTED_FILE_NAME}")


def analyze_vigenere(encrypted_message_file_name):
    debug_print("Loading encrypted message file...")
    message_encrypted = process_input_file(encrypted_message_file_name, "Encrypted message")

    print("[INFO] Analyzing message...")

    message_encrypted_ascii_array = string_to_upper_case_ascii_array(message_encrypted)
    debug_print(f"Encrypted message ASCII-Code array: {message_encrypted_ascii_array}")



    print(f"[INFO] DONE! Analyzed message saved in: {OUTPUT_ANALYZED_FILE_NAME}")


def write_string_to_file(output_file_name, encrypted_message):
    with open (output_file_name, "w") as file:
        file.write(encrypted_message)


def calculate_index_of_coincidence(secret_message):
    print("[INFO] Calculate Index of Coincidence")


def main():
    parser = argparse.ArgumentParser(description="Vigenère-Cipher: Message encryption and cryptanalysis tool")
    parser.add_argument("mode", type=str, help="Operation to perform on the provided message [(e)ncrypt, (d)ecrypt, or (a)nalyze)")
    parser.add_argument("message", type=str, help="The message you want to encrypt, decrypt, or analyse.")
    parser.add_argument("key", type=str, help="The key that should be used to encrypt or decrypt your message. Not needed for mode \"analyze\".")
    args = parser.parse_args()

    mode = args.mode
    debug_print(f"Mode: {mode}")

    if mode in ["e", "encrypt"]:
        encrypt_vigenere(args.message, args.key)
    elif mode in ["d", "decrypt"]:
        decrypt_vigenere(args.message, args.key)
    elif mode in ["a", "anylyze"]:
        analyze_vigenere(args.message)
    else:
        print("[INFO] [ERROR] Unknown mode. Please use (e)ncrypt, (d)ecrypt, or (a)nalyze only.")
        return
    

if __name__ == "__main__":
    main()
