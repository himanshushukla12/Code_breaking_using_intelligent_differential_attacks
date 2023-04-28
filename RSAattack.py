from Crypto.Util.number import *
import Crypto
import sys
import libnum

def assignValues(bits=64, msg='sampleCode'):
    p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    n1 = p*q
    e=3
    m=  bytes_to_long(msg.encode())
    c1=pow(m,e, n1)
    p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    n2 = p*q
    c2=pow(m,e, n2)
    p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    n3 = p*q
    c3=pow(m,e, n3)
    if ((m**e)<n3 or (m**e)<n2 or (m**e)<n1):
        print("Message is too short.")
        sys.exit()
    print(f"sender has used the RSA with three different modulus' to encrypt the same message for reciver. These modulus values are {n1}, {n2}, and {n3}. The corresponding ciphered values are {c1}, {c2}, and {c3}. Determine the message.")
    mod=[n1,n2,n3]
    rem=[c1,c2,c3]
    res=libnum.solve_crt(rem,mod)
    print("\n\nAnswer:")
    print(f"\nCipher 1: {c1}, N1={n1}")
    print(f"Cipher 2: {c2}, N2={n2}")
    print(f"Cipher 3: {c3}, N3={n3}")
    print(f"\nWe can solved M^e with CRT to get {res}")
    val=libnum.nroot(res,3)
    print(f"If we assume e=3, we take the third root to get: {val}")
    print(f"\nDecipher: {long_to_bytes(val)}")
    
# Example usage:
# bits = 1024
# msg = "SampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCodeSampleCode"
# assignValues(bits, msg)