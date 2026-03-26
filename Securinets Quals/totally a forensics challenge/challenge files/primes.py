from Crypto.Util.number import getPrime, isPrime
import random

bits = 1024
max_k = 1_000_000       # search range for closeness

p = getPrime(bits)
print("p =", p)

# search for a small k making q = p + k prime
for k in range(2, max_k, 2):  # step by 2 to keep q odd
    q = p + k
    if isPrime(q):
        print("k =", k)
        print("q =", q)
        break
else:
    print("Failed: try increasing max_k")
