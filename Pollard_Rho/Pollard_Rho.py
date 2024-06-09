from math import gcd
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA

def pollard_rho(n):
    def trial(g):
        t = 2
        h = 2

        while True:
            t = g(t)
            h = g(g(h))
            d = gcd(t - h, n)

            if d == n:
                return False
            elif d > 1:
                return d

    c = 1
    while True:
        def g(x):
            return (x ** 2 + c) % n

        d = trial(g)
        if d:
            return d
        c += 1

def get_pubkey(file):
    with open(file, 'rb') as f:
        key_data = f.read()
        public_key = RSA.import_key(key_data)
        N = public_key.n
        e = public_key.e
        return N, e

def get_ciphertext(file):
    with open(file, 'rb') as f:
        return bytes_to_long(f.read())

if __name__ == '__main__':
    pubkey_file = './key.pub'
    ciphertext_file = './input.enc'

    N, e = get_pubkey(pubkey_file)
    print(f"N: {N}")
    print(f"e: {e}")

    ct = get_ciphertext(ciphertext_file)
    print(f"ciphertext: {ct}")

    p = pollard_rho(N)
    if p is None:
        print("Pollard's Rho failed to find a factor")
    else:
        q = N // p
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        print(f"Private Key: {d}")

        pt = pow(ct, d, N)
        print(f"Decrypted message : {long_to_bytes(pt)} ")

        

