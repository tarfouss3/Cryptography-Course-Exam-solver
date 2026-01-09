#!/usr/bin/python3
from cryptocourse import basic_crypto, permute

# lazy S-box store (asks only when needed)
SBOX = {}

def read_hex_byte(s):
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if s == "":
        return 0
    return int(s, 16)

def sbox_lookup(byte_val):
    if byte_val not in SBOX:
        v = input(f"S-box[{hex(byte_val)}] = ").strip()
        SBOX[byte_val] = read_hex_byte(v)
    return SBOX[byte_val]

def apply_sbox(block_bytes):
    return bytes(sbox_lookup(b) for b in block_bytes)

def permute_bytes_robust(block_bytes, perm_seq):
    try:
        return permute.permute(block_bytes, perm_seq)
    except Exception:
        val = int.from_bytes(block_bytes, "big")
        pval = permute.permute(val, perm_seq)
        return pval.to_bytes(len(block_bytes), "big")

def parse_ops(s):
    tokens = s.strip().split()
    ops = []
    for t in tokens:
        t = t.upper()
        if t.startswith("XOR"):
            digits = ''.join(ch for ch in t if ch.isdigit())
            idx = int(digits) if digits else 1
            ops.append(("XOR", idx))
        elif t in ("SBOX", "PERM", "PERMUTE"):
            ops.append((t, None))
        else:
            raise ValueError(f"Unknown op token: {t}")
    return ops

def main():
    print("=== Final Generic Block-Cipher Solver ===")

    plaintext_hex = input("Plaintext (hex): ").strip()
    masterkey_hex = input("Master key (hex): ").strip()
    perm_seq = list(map(int, input("Permutation (space separated): ").split()))
    ops_input = input("Operation order (e.g. SBOX PERM XOR): ").strip()
    mode = input("Mode (ECB/CBC): ").strip().upper()

    plainb = bytes.fromhex(plaintext_hex)
    mkb = bytes.fromhex(masterkey_hex)

    block_size = len(perm_seq)  # bytes
    if block_size == 0:
        raise SystemExit("Permutation empty")

    if len(plainb) % block_size != 0:
        raise SystemExit("Plaintext length not multiple of block size")

    blocks = [plainb[i:i+block_size] for i in range(0, len(plainb), block_size)]
    print(f"\nDetected {len(blocks)} block(s) of {block_size*8} bits")

    ops = parse_ops(ops_input)

    xor_indices = [idx for (typ, idx) in ops if typ == "XOR"]
    num_subkeys = max(xor_indices) if xor_indices else 0

    if len(mkb) < num_subkeys * block_size:
        raise SystemExit("Master key too short for required subkeys")

    subkeys = []
    for i in range(num_subkeys):
        subkeys.append(mkb[i*block_size:(i+1)*block_size])

    if mode == "CBC":
        iv_hex = input("IV (hex, 0 if zero): ").strip().lower()
        if iv_hex == "0":
            iv = bytes(block_size)
        else:
            iv = bytes.fromhex(iv_hex)
            if len(iv) != block_size:
                raise SystemExit("IV length does not match block size")
    else:
        iv = bytes(block_size)

    cipher_blocks = []
    prev = iv

    for blk in blocks:
        state = blk

        if mode == "CBC":
            state = basic_crypto.byte_xor(state, prev)

        for step, idx in ops:
            if step == "SBOX":
                state = apply_sbox(state)
            elif step in ("PERM", "PERMUTE"):
                state = permute_bytes_robust(state, perm_seq)
            elif step == "XOR":
                state = basic_crypto.byte_xor(state, subkeys[idx-1])

        cipher_blocks.append(state)
        prev = state

    print("\nCiphertext blocks (hex):")
    for i, c in enumerate(cipher_blocks, 1):
        print(f"C{i} = {c.hex()}")

if __name__ == "__main__":
    main()
