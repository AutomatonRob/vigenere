### GLOBAL IMPORTS
import argparse
import re
import math
from collections import Counter

### LOCAL IMPORTS
from letter_frequencies import LETTER_FREQUENCIES_GERMAN

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
        print(f"\n[DEBUG] {message}")


def read_file(file_path):
    with open(file_path, "r") as file:
        return file.read()


def prepare_input_string(input_name, input_string):
    debug_print(f"Removing non-alphabet characters from {input_name}.")
    pattern = re.compile('[^a-zA-Z]')

    return pattern.sub('', input_string)


def string_to_upper_case_ascii_array(input_string):
    return [ord(char) for char in input_string.upper()]


def shift_enc(message_char_ascii, key_char_ascii):
    return (((message_char_ascii - BASE_SHIFT) + (key_char_ascii - BASE_SHIFT)) % 26) + BASE_SHIFT


def shift_dec(message_encrypted_char_ascii, key_char_ascii):
    return ((message_encrypted_char_ascii - BASE_SHIFT) - (key_char_ascii - BASE_SHIFT) + 26) % 26 + BASE_SHIFT


def ascii_array_to_string(ascii_array):
    return "".join(chr(ascii_code) for ascii_code in ascii_array)


def process_input_file(file_name, file_type):
    string_raw = read_file(file_name)
    string = prepare_input_string(file_type, string_raw)
    
    debug_print(f"Original {file_type}: {string}")
    
    return string


def encrypt_vigenere(message_file_name, key_file_name):
    encrypted_message_array = []
    
    debug_print("Loading message and key file")
    message = process_input_file(message_file_name, "Message")
    key = process_input_file(key_file_name, "Key")

    print("[INFO] Encrypting message")

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

    print(f"\n[INFO] DONE! Encrypted message saved in: {OUTPUT_ENCRYPTED_FILE_NAME}")


def decrypt_vigenere(encrypted_message_file_name, key_file_name):
    decrypted_message_array = []
    
    debug_print("Loading encrypted message and key file")
    message_encrypted = process_input_file(encrypted_message_file_name, "Encrypted message")
    key = process_input_file(key_file_name, "Key")

    print("[INFO] Decrypting message")

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

    print(f"\n[INFO] DONE! Decrypted message saved in: {OUTPUT_DECRYPTED_FILE_NAME}")


def analyze_vigenere(encrypted_message_file_name):
    debug_print(f"Loading encrypted message file")
    message_encrypted = process_input_file(encrypted_message_file_name, "Encrypted message")

    print(f"\n[INFO] Analyzing message")

    # message_encrypted_ascii_array = string_to_upper_case_ascii_array(message_encrypted)
    # debug_print(f"Encrypted message ASCII-Code array: {message_encrypted_ascii_array}")
    
    possible_password_lengths = execute_kasiski_test(message_encrypted)

    # Remove all possible password lengths that were calculated more than once
    possible_password_length_sanitized = {length: count for length, count in possible_password_lengths.items() if count > 1}

    ic_list = {}

    for possible_password_length in possible_password_length_sanitized.keys():
        ic = calculate_mutual_index_of_coincidence(message_encrypted, possible_password_length)
        ic_list[possible_password_length] = ic

    debug_print(f"Mutual indices of coincidence: {ic_list}")

    # TODO
    # print(f"\n[INFO] DONE! Analyzed message saved in: {OUTPUT_ANALYZED_FILE_NAME}")

    return


def write_string_to_file(output_file_name, encrypted_message):
    with open (output_file_name, "w") as file:
        file.write(encrypted_message)


def find_reoccurring_segments(encrypted_message, segment_length):
    segments = {}
    reoccurring_segments = {}
    encrypted_message_length = len(encrypted_message)

    for i in range(encrypted_message_length - segment_length):
        current_segment = encrypted_message[i:i + segment_length]
        if current_segment in segments:
            segments[current_segment].append(i)
        else:
            segments[current_segment] = [i]

    for segment, positions in segments.items():
        if len(positions) > 1:
            reoccurring_segments[segment] = positions

    return reoccurring_segments


def get_distances(positions):
    return [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]


def calculate_greatest_common_divisor(distances):
    gcd = distances[0]

    for distance in distances[1:]:
        gcd = math.gcd(gcd, distance)

    return gcd


def execute_kasiski_test(encrypted_message, segment_length=3):
    print(f"\n[INFO] Executing Kasiski-Test on encrypted message")
    reoccurring_segments = find_reoccurring_segments(encrypted_message, segment_length)
    distances = {}
    possible_password_lengths = {}

    print(f"\nThe following segments reoccurred:")

    for segment, positions in reoccurring_segments.items():
        #debug_print(f"[POSITIONS] {segment}: {positions}")

        distances[segment] = get_distances(positions)

        #debug_print(f"[DISTANCES] {segment}: {distances[segment]}")

        greatest_common_divisor = calculate_greatest_common_divisor(distances[segment])

        #debug_print(f"[GCD] Possible password length: {greatest_common_divisor}")

        if greatest_common_divisor in possible_password_lengths:
            possible_password_lengths[greatest_common_divisor] += 1
        else:
            possible_password_lengths[greatest_common_divisor] = 1

    debug_print(f"Calculated distances between reoccurring segments: {distances}")

    possible_password_lengths_sorted = dict(sorted(possible_password_lengths.items()))
    # debug_print(f"Sorted dictionary of possible password lengths and their abundance: {possible_password_lengths_sorted}")

    return possible_password_lengths_sorted


def calculate_mutual_index_of_coincidence(message_encrypted, password_length):
    # print("[INFO] Calculating index of coincidence")

    ic_total = 0

    # Create an array with as many empty strings as the assumed password length
    blocks = ['' for _ in range(password_length)]

    # Add all characters that were encrypted with the same password character to a separate string
    for i, char in enumerate(message_encrypted):
        blocks[i % password_length] += char

    for block in blocks:
        block_length = len(block)

        if block_length < 2:
            break
        
        char_distribution = {char: block.count(char) for char in set(block)}
        ic_block = sum((count * (count - 1) for count in char_distribution.values())) / (block_length * (block_length - 1))

        ic_total += ic_block

    return ic_total / password_length


def calculate_index_of_coincidence(secret_message):

    secret_message_length = len(secret_message)
    secret_message_letters_count = dict(sorted(Counter(secret_message).items()))
    index_of_coincidence = sum((count * (count - 1) for count in secret_message_letters_count.values())) / (secret_message_length * (secret_message_length - 1))

    debug_print(f"Index of Coincidence (IC): {index_of_coincidence}")

def main():
    parser = argparse.ArgumentParser(description="Vigenère-Cipher: Message encryption and cryptanalysis tool")
    parser.add_argument("mode", type=str, help="Operation to perform on the provided message [(e)ncrypt, (d)ecrypt, or (a)nalyze)")
    parser.add_argument("message", type=str, help="The message you want to encrypt, decrypt, or analyse.")
    parser.add_argument("--key", type=str, help="The key that should be used to encrypt or decrypt your message. Not needed for mode \"analyze\".")
    args = parser.parse_args()

    mode = args.mode
    debug_print(f"Mode: {mode}")

    if mode in ["e", "encrypt"]:
        if not args.key:
            print("[ERROR] Key is required for encryption! Exiting.")
            return
        encrypt_vigenere(args.message, args.key)
    elif mode in ["d", "decrypt"]:
        if not args.key:
            print("[ERROR] Key is required for decryption! Exiting.")
            return
        decrypt_vigenere(args.message, args.key)
    elif mode in ["a", "analyze"]:
        analyze_vigenere(args.message)
    else:
        print("[INFO] [ERROR] Unknown mode. Please use (e)ncrypt, (d)ecrypt, or (a)nalyze only.")
        return
    

if __name__ == "__main__":
    main()
