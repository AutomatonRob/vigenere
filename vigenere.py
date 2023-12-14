import argparse
import re
import math
from collections import Counter

from letter_frequencies import LETTER_FREQUENCIES_GERMAN

MODES = ["e", "encrypt", "d", "decrypt", "a", "analyse"]
BASE_SHIFT = ord("A")
OUTPUT_ENCRYPTED_FILE_NAME = "vigenere_message_encrypted.txt"
OUTPUT_DECRYPTED_FILE_NAME = "vigenere_message_decrypted.txt"
OUTPUT_ANALYZED_TEXT_FILE_NAME = "vigenere_message_analyzed_text.txt"
OUTPUT_ANALYZED_KEY_FILE_NAME = "vigenere_message_analyzed_key.txt"
LETTER_FREQUENCIES_GERMAN = {
    "A": 0.0643,
    "B": 0.0185,
    "C": 0.0326,
    "D": 0.0512,
    "E": 0.1774,
    "F": 0.0156,
    "G": 0.0269,
    "H": 0.0522,
    "I": 0.0760,
    "J": 0.0023,
    "K": 0.0140,
    "L": 0.0349,
    "M": 0.0275,
    "N": 0.1001,
    "O": 0.0239,
    "P": 0.0064,
    "Q": 0.0001,
    "R": 0.0698,
    "S": 0.0688,
    "T": 0.0594,
    "U": 0.0427,
    "V": 0.0064,
    "W": 0.0173,
    "X": 0.0002,
    "Y": 0.0004,
    "Z": 0.0110,
}

def read_file(file_path):
    with open(file_path, "r") as file:
        return file.read()

def write_string_to_file(output_file_name, encrypted_message):
    with open (output_file_name, "w") as file:
        file.write(encrypted_message)

def process_input_file(file_name):
    file_content = read_file(file_name)
    pattern = re.compile('[^a-zA-Z]')

    return pattern.sub('', file_content)

def string_to_upper_case_ascii_array(input_string):
    return [ord(char) for char in input_string.upper()]

def ascii_array_to_string(ascii_array):
    return "".join(chr(ascii_code) for ascii_code in ascii_array)

def shift_enc(message_char_ascii, key_char_ascii):
    return (((message_char_ascii - BASE_SHIFT) + (key_char_ascii - BASE_SHIFT)) % 26) + BASE_SHIFT

def shift_dec(message_encrypted_char_ascii, key_char_ascii):
    return ((message_encrypted_char_ascii - BASE_SHIFT) - (key_char_ascii - BASE_SHIFT) + 26) % 26 + BASE_SHIFT

def encrypt_vigenere(message_file_name, key_file_name, encrypted_message_file_name=OUTPUT_ENCRYPTED_FILE_NAME):
    print(f"\n[INFO] Encrypting message!")
    encrypted_message_array = []
    message = process_input_file(message_file_name)
    key = process_input_file(key_file_name)
    message_ascii_array = string_to_upper_case_ascii_array(message)
    key_ascii_array = string_to_upper_case_ascii_array(key)
    key_ascii_array_len = len(key_ascii_array)

    for msg_index, message_char_ascii in enumerate(message_ascii_array):
        key_char_ascii = key_ascii_array[msg_index % key_ascii_array_len]
        encrypted_char_ascii = shift_enc(message_char_ascii, key_char_ascii)
        encrypted_message_array.append(encrypted_char_ascii)

    encrypted_message_string = ascii_array_to_string(encrypted_message_array)
    write_string_to_file(encrypted_message_file_name, encrypted_message_string)

    print(f"\n[INFO] Encrypted message saved to file: {encrypted_message_file_name}")

    return encrypted_message_string

def decrypt_vigenere(encrypted_message_file_name, key_file_name, output_file_name=OUTPUT_DECRYPTED_FILE_NAME):
    print(f"\n[INFO] Decrypting message!")
    
    decrypted_message_array = []
    message_encrypted = process_input_file(encrypted_message_file_name)
    key = process_input_file(key_file_name)
    message_encrypted_ascii_array = string_to_upper_case_ascii_array(message_encrypted)
    key_ascii_array = string_to_upper_case_ascii_array(key)
    key_ascii_array_len = len(key_ascii_array)

    for msg_enc_index, msg_enc_char_ascii in enumerate(message_encrypted_ascii_array):
        key_char_ascii = key_ascii_array[msg_enc_index % key_ascii_array_len]
        decrypted_char_ascii = shift_dec(msg_enc_char_ascii, key_char_ascii)
        decrypted_message_array.append(decrypted_char_ascii)
    
    decrypted_message_string = ascii_array_to_string(decrypted_message_array)
    write_string_to_file(output_file_name, decrypted_message_string)

    print(f"\n[INFO] Decrypted message saved to file: {output_file_name}")

    return decrypted_message_string

def analyze_vigenere(encrypted_message_file_name):
    print(f"\n[INFO] Analyzing message!")
    
    message_encrypted = process_input_file(encrypted_message_file_name)

    ### KASISKI TEST
    kasiski_key_lens = execute_kasiski_test(message_encrypted)
    kasiski_key_len_top = next(iter(kasiski_key_lens))
    kasiski_key_lens_sum = sum(kasiski_key_lens.values())
    kasiski_key_lens_list = list(key_len for key_len in kasiski_key_lens.keys())

    print(f"\n[KASISKI-TEST]\n{len(kasiski_key_lens)} possible key lengths found with Kasiski-Test. Here are the top results:")
    print(f"{'Length':<15} {'Results':<15} {'% of all results':<15}")
    for key_len, calculations in list(kasiski_key_lens.items())[:5]:
        print(f" {key_len:<15} {calculations:<15} {round(calculations/kasiski_key_lens_sum*100, 2):<15}")

    ### INDEX OF COINCIDENCE - SINGLE-TEXT
    ic_message = calculate_index_of_coincidence(message_encrypted)
    ics_predicted = {}
    msg_len = len(message_encrypted)

    for key_len in kasiski_key_lens_list:
        ics_predicted[key_len] = (((1 / key_len) * ((msg_len - key_len) / (msg_len - 1))) * 0.07733) + (((key_len - 1) / key_len) * (msg_len / (msg_len - 1)) * 0.03846)

    ics_top = {}
    for length, ic_predicted in ics_predicted.items():
        ics_top[length] = abs(ic_message - ic_predicted)

    ics_top = dict(sorted(ics_top.items(), key=lambda item: item[1], reverse=False))

    print(f"\n[INDEX OF COINCIDENCE - SINGLE-TEXT]\nComparing the possible key lengths from the Kasiski-Test against the calculated index of coincidence Ic = {round(ic_message, 8)}:")
    print(f"{'Length':<15} {'Ic (predicted)':<15} {'Deviation':<15} {'Deviation (%)':<15}")
    for length in list(ics_top.keys())[:5]:
            print(f"{length:<15} {round(ics_predicted[length], 8):<15} {round(ics_top[length], 8):<15} {round((ics_top[length] / ics_predicted[length] * 100), 2):<15}")
    
    ### INDEX OF COINCIDENCE - BY ROW
    ic_row_all = {}

    for length in kasiski_key_lens_list:
        ic_row = calculate_index_of_coincidence_by_row(message_encrypted, length)
        ic_row_all[length] = ic_row
    
    ic_row_all = dict(sorted(ic_row_all.items(), key=lambda item: item[1], reverse=True))

    print(f"\n[INDEX OF COINCIDENCE - BY ROW]\nComparing the possible key lengths from the Kasiski-Test against the highest averages of indices of coincidence:")
    print(f"{'Length':<15} {'Ic (calculated)':<15}")
    for length, ic_row in list(ic_row_all.items())[:5]:
        print(f"{length:<15} {round(ic_row, 8):<15}")

    # CALCULATE KEY
    key = calculate_key(message_encrypted, kasiski_key_len_top)
    print(f"\n[RESULT] Calculated key: {key}")
    write_string_to_file(OUTPUT_ANALYZED_KEY_FILE_NAME, key)
    print(f"\n[INFO] Analyzed key saved to file: {OUTPUT_ANALYZED_KEY_FILE_NAME}")

    # DECRYPT MESSAGE
    analyzed_message = decrypt_vigenere(encrypted_message_file_name, OUTPUT_ANALYZED_KEY_FILE_NAME, OUTPUT_ANALYZED_TEXT_FILE_NAME)

    print(f"\n[RESULT] Decrypted message:\n{analyzed_message}")

    return

def find_reoccurring_segments(encrypted_message, segment_len):
    segments = {}
    reoccurring_segments = {}
    encrypted_message_len = len(encrypted_message)

    for i in range(encrypted_message_len - segment_len):
        current_segment = encrypted_message[i:i + segment_len]
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

def execute_kasiski_test(encrypted_message, segment_len=3):
    reoccurring_segments = find_reoccurring_segments(encrypted_message, segment_len)
    distances = {}
    possible_key_lens = {}

    for segment, positions in reoccurring_segments.items():
        positions_len = len(positions)
        if positions_len <= 2:
            continue

        distances[segment] = get_distances(positions)
        greatest_common_divisor = calculate_greatest_common_divisor(distances[segment])

        if greatest_common_divisor in possible_key_lens:
            possible_key_lens[greatest_common_divisor] += 1
        else:
            possible_key_lens[greatest_common_divisor] = 1

    # Return possible key lengths sorted by decreasing frequency
    return dict(sorted(possible_key_lens.items(), key=lambda possible_key_len: possible_key_len[1], reverse=True))

def split_message(message, length):
    rows = ['' for _ in range(length)]

    # Add all characters that were encrypted with the same key character into one row
    for i, char in enumerate(message):
        rows[i % length] += char

    return rows

def calculate_index_of_coincidence_by_row(message_encrypted, key_len):
    ic_by_row = 0

    # Create an array with as many empty strings as the assumed key length
    rows = split_message(message_encrypted, key_len)

    for row in rows:
        row_len = len(row)

        # Don't process a row if there are less than two characters inside.
        if row_len < 2:
            continue
        
        ic_by_row += calculate_index_of_coincidence(row)

    return ic_by_row / key_len

def calculate_index_of_coincidence(message_encrypted):
    message_encrypted_len = len(message_encrypted)
    message_encrypted_letters_count = dict(sorted(Counter(message_encrypted).items()))
    
    return sum((count * (count - 1) for count in message_encrypted_letters_count.values())) / (message_encrypted_len * (message_encrypted_len - 1))

def calculate_key(message_encrypted, key_len):
    rows = split_message(message_encrypted, key_len)
    rows_letter_frequencies = []

    for row in rows:
        letter_frequencies = dict(sorted(Counter(row).items()))
        rows_letter_frequencies.append(letter_frequencies)

    key_ascii_array = []
    p = LETTER_FREQUENCIES_GERMAN

    for row_nr in range(key_len):
        f = fill_letter_frequencies(rows_letter_frequencies[row_nr])
        n = len(rows[row_nr])

        M_g = {}

        for g in range(26):
            M_g[g] = sum(p[chr(i + BASE_SHIFT)] * f[chr((i + g) % 26 + BASE_SHIFT)] / n for i in range(26))

        key_ascii_array.append(max(M_g.items(), key=lambda x: x[1])[0] + BASE_SHIFT)

    return ascii_array_to_string(key_ascii_array)

# Helper function to add missing letters
def fill_letter_frequencies(letter_frequencies):
    for i in range(26):
        letter = chr(i + BASE_SHIFT)
        if letter_frequencies.get(letter) is None:
            letter_frequencies[letter] = 0

    return dict(sorted(letter_frequencies.items()))

def main():
    parser = argparse.ArgumentParser(description="Vigenère-Cipher: Message encryption and cryptanalysis tool")
    parser.add_argument("mode", type=str, help="Operation to perform on the provided message [(e)ncrypt, (d)ecrypt, or (a)nalyze)")
    parser.add_argument("message", type=str, help="The message you want to encrypt, decrypt, or analyse.")
    parser.add_argument("--key", type=str, help="The key that should be used to encrypt or decrypt your message. Not needed for mode \"analyze\".")
    args = parser.parse_args()

    mode = args.mode

    if mode in ["e", "encrypt"]:
        if not args.key:
            print(f"\n[ERROR] Key is required for encryption! Exiting.")
            return
        encrypt_vigenere(args.message, args.key)
    elif mode in ["d", "decrypt"]:
        if not args.key:
            print(f"\n[ERROR] Key is required for decryption! Exiting.")
            return
        decrypt_vigenere(args.message, args.key)
    elif mode in ["a", "analyze"]:
        analyze_vigenere(args.message)
    else:
        print(f"\n[ERROR] Unknown mode. Please use (e)ncrypt, (d)ecrypt, or (a)nalyze only.")
        return
    
if __name__ == "__main__":
    main()
