#!/usr/bin/python3
from cryptocourse import shamir, basic_mpc
def reconstruct_and_query():
    print("=== SPDZ / Beaver Triple Solver ===")
    prime = int(input("Prime p: ").strip())

    shares1 = eval(input("Shares1 (e.g. [[1,2],[2,4],[3,10]]): ").strip())
    shares2 = eval(input("Shares2 (e.g. [[1,3],[2,9],[3,25]]): ").strip())
    beaver = eval(input("Beaver triple: ").strip())

    # Split Beaver triple
    sha, shb, shc = basic_mpc.splitBeaver(beaver)

    # Compute alpha/beta shares
    alphashares = shamir.subtractShares(shares1, sha, prime)
    betashares  = shamir.subtractShares(shares2, shb, prime)

    # Reconstruct secrets alpha and beta
    alpha = shamir.reconstructSecret(alphashares, prime)
    beta  = shamir.reconstructSecret(betashares, prime)

    # Compute multiplication shares using linear combination
    resultShares = shamir.linearCombinationOfShares([shc, shb, sha], [1, alpha, beta], alpha * beta, prime)

    print("\nResult shares:")
    for s in resultShares:
        print(s)

    # Build polynomial from shares for evaluation
    xs, ys = zip(*resultShares)
    def lagrange_eval(x):
        total = 0
        for i in range(len(xs)):
            xi, yi = xs[i], ys[i]
            prod = yi
            for j in range(len(xs)):
                if i != j:
                    xj = xs[j]
                    numerator = (x - xj) % prime
                    denominator = (xi - xj) % prime
                    inv_den = pow(denominator, -1, prime)
                    prod = (prod * numerator * inv_den) % prime
            total = (total + prod) % prime
        return total

    while True:
        choice = input("\nDo you want to evaluate another x? (y/n): ").strip().lower()
        if choice != "y":
            break
        x_val = int(input("Enter x value: ").strip())
        y_val = lagrange_eval(x_val)
        print(f"y-value at x={x_val}: {y_val}")

if __name__ == "__main__":
    reconstruct_and_query()
