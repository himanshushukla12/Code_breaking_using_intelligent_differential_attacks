from Crypto.Cipher import DES
import itertools

# Define target plaintext and ciphertext
target_plaintext = b"Hello!"
target_ciphertext = b"\x9f\xf8\xe6\xdc\x6c\xbd\xf1\x7a"

# Generate all possible 56-bit keys
all_keys = list(itertools.product([0, 1], repeat=56))

# Divide keys into two halves for double encryption
first_half_keys = all_keys[:len(all_keys)//2]
second_half_keys = all_keys[len(all_keys)//2:]

# Create DES cipher object
cipher = DES.new(b"\x00\x00\x00\x00\x00\x00\x00\x00", DES.MODE_ECB)

# Dictionary to store intermediate values of double DES
intermediate_values = {}

# Encrypt with first half of keys and store intermediate values
for key in first_half_keys:
    des_key = bytes(key) + bytes([0] * 8)
    des_cipher = DES.new(des_key, DES.MODE_ECB)
    intermediate_value = des_cipher.encrypt(target_plaintext)
    intermediate_values[intermediate_value] = key

# Decrypt with second half of keys and check for matches
for key in second_half_keys:
    des_key = bytes(key) + bytes([0] * 8)
    des_cipher = DES.new(des_key, DES.MODE_ECB)
    intermediate_value = des_cipher.decrypt(target_ciphertext)
    if intermediate_value in intermediate_values:
        first_key = intermediate_values[intermediate_value]
        double_des_key = bytes(first_key) + bytes(key)
        double_des_cipher = DES.new(double_des_key, DES.MODE_ECB)
        recovered_plaintext = double_des_cipher.decrypt(target_ciphertext)
        print("Recovered key:", double_des_key.hex())
        print("Recovered plaintext:", recovered_plaintext.decode("utf-8"))
        break
