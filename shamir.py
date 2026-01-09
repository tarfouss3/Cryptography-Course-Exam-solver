#!/usr/bin/python3
from cryptocourse import shamir

def read_int(s):
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s)

def main():
    print("=== Shamir Secret Reconstruction ===")
    prime = read_int(input("Prime field p: "))

    shares = []
    n = int(input("How many shares do you have? "))
    for i in range(n):
        x = read_int(input(f"Share {i+1} x: "))
        y = read_int(input(f"Share {i+1} y: "))
        shares.append([x, y])

    secret = shamir.reconstructSecret(shares, prime)
    print(f"\nRecovered secret: {secret}")

if __name__ == "__main__":
    main()
