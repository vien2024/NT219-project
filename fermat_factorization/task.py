from Crypto.Util.number import isPrime, getStrongPrime
from gmpy2 import next_prime

content = b''
with open('secret.txt', 'rb') as file:
    # Read the entire file content
    content = file.read()
    # Print the content
    print(content)

# Anti-Fermat Key Generation
p = getStrongPrime(1024)
q = next_prime(p ^ ((1<<1024)-1))
n = p * q
e = 65537

# Encryption
m = int.from_bytes(content, 'big')
print(f"m: {m}")
assert m < n
c = pow(m, e, n)
c_int = int(c)

print('n = {}'.format(hex(n)))
print('c = {}'.format(hex(c)))

c_bytes = c_int.to_bytes((c.bit_length() + 7) // 8, 'big')

with open('encrypted.txt', 'wb') as file:
    file.write(c_bytes)