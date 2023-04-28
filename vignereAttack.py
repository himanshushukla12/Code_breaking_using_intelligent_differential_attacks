import string

#key=EJTVFZQBCMBXGDTT

def key_recovery(pair):
    plaintext, ciphertext = pair
    key = ''
    for p, c in zip(plaintext, ciphertext):
        key_char = (ord(c) - ord(p)) % 26
        key += chr(key_char + 65)
    return key

pair="BAKSHIEXAMPLE","FJDNMHUYCYQIK"
print(key_recovery(pair))
# Intelligently chosen plaintexts (repeated patterns)
chosen_plaintexts = [
    "ABABABABABABABABABAB",
    "BCBCBCBCBCBCBCBCBCBC",
    "BABABABABABABABABABA",
    "CACACACACACACACACACA",
    "ADADADADADADADADADAD",
    "BEBEBEBEBEBEBEBEBEBE",
    "AFAFAFAFAFAFAFAFAFAF",
    "BGBGBGBGBGBGBGBGBGBG",
    "AHAHAHAHAHAHAHAHAHAH",
    "BHBHBHBHBHBHBHBHBHBH",
]

