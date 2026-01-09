#!/usr/bin/python3
from cryptocourse import basic_ec, basic_dh
from operator import xor

def hex_to_int(h):
    """Convert hex string to integer."""
    h = h.strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    return int(h, 16)

def int_to_hex(i):
    """Convert integer to hex string."""
    return hex(i)

def xor_bytes_int(a_int, b_int):
    """XOR two integers."""
    return a_int ^ b_int

def ecdh_solver():
    print("=== Elliptic Curve Diffie-Hellman Solver ===")
    curve_name = input("Curve name (default secp256k1): ").strip()
    if not curve_name:
        curve_name = "secp256k1"
    ec = basic_ec.StandardECS[curve_name]
    g = basic_ec.StandardBasePoints[curve_name]

    a_priv = int(input("Private key of party A: "))
    b_priv = int(input("Private key of party B: "))

    a = basic_ec.DiffieHellman(ec, g)
    b = basic_ec.DiffieHellman(ec, g)
    a.set_private_key(a_priv)
    b.set_private_key(b_priv)

    a_pub = a.gen_public_key()
    b_pub = b.gen_public_key()

    secret_ab = a.gen_shared_key(b_pub)
    secret_ba = b.gen_shared_key(a_pub)

    if secret_ab != secret_ba:
        print("Warning: Shared secrets do not match!")

    print("\nShared secret (coord form):")
    print(f"x = {secret_ab.x}")
    print(f"y = {secret_ab.y}\n")

    choice = input("Do you want to XOR with plaintext? (y/n): ").strip().lower()
    if choice == "y":
        plain_hex = input("Plaintext (hex): ").strip()
        plain_int = hex_to_int(plain_hex)
        key_int = secret_ab.x  # Using x-coordinate as stream
        if key_int.bit_length() < plain_int.bit_length():
            print("Warning: key shorter than plaintext, truncating plaintext to key length.")
            shift = plain_int.bit_length() - key_int.bit_length()
            plain_int = plain_int >> shift
        cipher_int = xor_bytes_int(plain_int, key_int)
        print("Ciphertext (hex):", int_to_hex(cipher_int))

def classic_dh_solver():
    print("=== Classic Discrete-Log Diffie-Hellman Solver ===")
    group_size = input("Group size (default 6144): ").strip()
    if not group_size:
        group_size = 6144
    else:
        group_size = int(group_size)

    sequence = input("Sequence (default 2): ").strip()
    if not sequence:
        sequence = 2
    else:
        sequence = int(sequence)

    a_priv = int(input("Private key of party A: "))
    b_priv = int(input("Private key of party B: "))

    a = basic_dh.DiffieHellman(group_size, sequence)
    b = basic_dh.DiffieHellman(group_size, sequence)
    a.set_private_key(a_priv)
    b.set_private_key(b_priv)

    publica = a.gen_public_key()
    publicb = b.gen_public_key()

    secretab = a.gen_shared_key(publicb)
    secretba = b.gen_shared_key(publica)

    if secretab != secretba:
        print("Warning: Shared secrets do not match!")

    print("\nShared secret (hex):", secretab.hex())

    choice = input("Do you want to XOR with plaintext? (y/n): ").strip().lower()
    if choice == "y":
        plain_hex = input("Plaintext (hex): ").strip()
        plain_int = hex_to_int(plain_hex)
        key_int = int.from_bytes(secretab, "big")

        if key_int.bit_length() < plain_int.bit_length():
            print("Warning: key shorter than plaintext! Truncating plaintext to key length.")
            shift = plain_int.bit_length() - key_int.bit_length()
            plain_int = plain_int >> shift

        cipher_int = xor_bytes_int(plain_int, key_int)
        print("Ciphertext (hex):", int_to_hex(cipher_int))

def main():
    print("=== Universal Diffie-Hellman Solver ===")
    dh_type = input("Choose type (ECDH / DH): ").strip().upper()
    if dh_type == "ECDH":
        ecdh_solver()
    elif dh_type == "DH":
        classic_dh_solver()
    else:
        print("Invalid choice, exiting.")

if __name__ == "__main__":
    main()
