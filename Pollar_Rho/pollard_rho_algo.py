from math import gcd
from rsa.prime import getprime

def pollard_rho(n):
    def trial(g):
        t = 2
        h = 2

        while True:
            t = g(t)
            h = g(g(h))
            d = gcd(t-h, n)

            if d == n:
                return False
            elif d > 1:
                return d
            
    c = 1
    while(True):
        def g(x):
            return (x**2 + c) % n
        
        d = trial(g)
        if d:
            return d
        c += 1




bits = 48
def test():
    # p, q = getprime(bits // 2), getprime(bits // 2)
    # n = p * q
    n = 3233
    # print(f"p ={p}, q= {q}, n={n}")
    print(f"n={n}")
    print(f"Factoring {n} ...")
    d = pollard_rho(n)
    print(f"Found d={d}")


test()