#!/usr/bin/python3
from cryptocourse import euclidean

def read_hex_or_dec(s):
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s)

def main():
    print("=== RSA Full Solver ===")
    choice = input("Do you have primes p and q? (y/n): ").strip().lower()

    if choice == "y":
        p = read_hex_or_dec(input("Prime p (hex or decimal): ").strip())
        q = read_hex_or_dec(input("Prime q (hex or decimal): ").strip())
        n = p * q
        tot_n = euclidean.lcm(p-1, q-1)
    else:
        n = read_hex_or_dec(input("Modulus n (hex or decimal): ").strip())
        tot_choice = input("Do you have φ(n) or lcm(p-1,q-1)? (phi/lcm): ").strip().lower()
        if tot_choice == "phi":
            tot_n = read_hex_or_dec(input("φ(n) (hex or decimal): ").strip())
        elif tot_choice == "lcm":
            tot_n = read_hex_or_dec(input("lcm(p-1,q-1) (hex or decimal): ").strip())
        else:
            raise SystemExit("Unknown option, can't compute d")

    e = read_hex_or_dec(input("Public exponent e (hex or decimal, usually 65537): ").strip())
    d = euclidean.mulinv(e, tot_n)
    print(f"\nPrivate exponent d: {d}")

    both = input("Do you want to do BOTH encryption and decryption? (y/n): ").strip().lower()
    if both == "y":
        plaintext = read_hex_or_dec(input("Plaintext for encryption: ").strip())
        ciphertext = read_hex_or_dec(input("Ciphertext for decryption: ").strip())

        enc = pow(plaintext, e, n)
        dec = pow(ciphertext, d, n)

        print(f"\nEncryption result -> Ciphertext (decimal): {enc}, (hex): {hex(enc)}")
        print(f"Decryption result -> Plaintext (decimal): {dec}, (hex): {hex(dec)}")
    else:
        action = input("Encrypt or Decrypt? (E/D): ").strip().upper()
        number = read_hex_or_dec(input("Number (plaintext for encryption / ciphertext for decryption): ").strip())

        if action == "E":
            cipher = pow(number, e, n)
            print(f"\nCiphertext (decimal): {cipher}")
            print(f"Ciphertext (hex): {hex(cipher)}")
        elif action == "D":
            plain = pow(number, d, n)
            print(f"\nDecrypted plaintext (decimal): {plain}")
            print(f"Decrypted plaintext (hex): {hex(plain)}")
        else:
            raise SystemExit("Unknown action")

if __name__ == "__main__":
    main()
