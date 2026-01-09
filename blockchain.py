#!/usr/bin/python3
from cryptocourse import basic_bc

def main():
    print("=== Blockchain Mining Solver ===")

    name1 = input("Sender name: ")
    seed1 = int(input("Sender seed: "))
    name2 = input("Receiver name: ")
    seed2 = int(input("Receiver seed: "))

    amount = int(input("Amount: "))
    tx_time = int(input("Transaction timestamp: "))

    block_index = int(input("Block index: "))
    block_time = int(input("Block timestamp: "))
    prev_hash = input("Previous hash: ")
    miner = input("Miner name: ")
    hash_func = input("Hash function (sha256/sha512): ").strip()

    sender = basic_bc.MyIdentity(name1, seed1)
    receiver = basic_bc.MyIdentity(name2, seed2)

    tx = basic_bc.MyTransaction(sender, receiver, amount,
                                timestamp=tx_time,
                                hash_function=hash_func)
    tx.sign()

    block = basic_bc.Block(block_index, [tx], prev_hash,
                           miner,
                           timestamp=block_time,
                           hash_function=hash_func)

    block.mine()

    print("\nBlock mined successfully")
    print("Nonce:", block.nonce)

if __name__ == "__main__":
    main()
