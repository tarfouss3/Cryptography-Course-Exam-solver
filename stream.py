#!/usr/bin/python3
import random

def clean_hex(h):
    h = h.lower().replace("0x", "").strip()
    if len(h) % 2 != 0:
        print("[!] WARNING: odd-length hex detected, trimming last character")
        h = h[:-1]
    return h

def hex_to_bytes(h):
    return bytes.fromhex(clean_hex(h))

def main():
    print("=== XOR Stream Cipher Solver ===")

    plaintext_hex = input("Plaintext (hex): ")
    plaintext = hex_to_bytes(plaintext_hex)

    choice = input("Stream provided? (y/n): ").strip().lower()

    if choice == 'y':
        stream_hex = input("Stream (hex): ")
        stream = hex_to_bytes(stream_hex)

        if len(stream) < len(plaintext):
            print(f"[!] WARNING: stream too short "
                  f"({len(stream)} < {len(plaintext)} bytes)")

        stream = stream[:len(plaintext)]
    else:
        seed = int(input("Random seed: "))
        bits = int(input("Number of bits: "))

        random.seed(seed)
        stream_int = random.getrandbits(bits)
        stream = stream_int.to_bytes((bits + 7) // 8, "big")[:len(plaintext)]

    cipher = bytes(p ^ s for p, s in zip(plaintext, stream))

    fmt = input("Output format (hex / bin / int / bytes): ").strip().lower()
    if fmt == "hex":
        print("Ciphertext:", cipher.hex())
    elif fmt == "bytes":
        print("Ciphertext:", cipher)
    elif fmt == "int":
        print("Ciphertext:", int.from_bytes(cipher, "big"))
    elif fmt == "bin":
        print("Ciphertext:", bin(int.from_bytes(cipher, "big")))
    else:
        print("Unknown format")

if __name__ == "__main__":
    main()
