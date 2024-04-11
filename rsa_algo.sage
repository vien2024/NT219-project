from sage.all import *

# Generate p and q
p = random_prime(10^50-1,False,10^48)
q = random_prime(10^50-1,False,10^48)

# Ensure that p is not equal to q
while(p==q):
    q = random_prime(2^512-1,False,2^511)


# Check primality
print('----------------------------------------------------------------------------------------------------------------------')
print(f'The generated Prime number p = {p} is a true prime ? Solution = {is_prime(p)}')
print(f'The generated Prime number p = {q} is a true prime ? Solution = {is_prime(q)}')

# Calculate n and phi of n
n = p * q
phi = (p-1) * (q-1)

print(f' n = {n} ')
print(f'The totient of n = {phi}')

# Find e such that e is coprime to n
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

print(f"e = {e}")

# Find d
bezout = xgcd(e, phi)
d = Integer(mod(bezout[1], phi))

# Accept message

m = input("Enter your message: ")

alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ,.?!:;-\'\"'
def string2number(string):
    M=0
    for i in range(len(string)):
        M = 100*M + alphabet.index(string[i])
    return M
def number2string(M):
    string=''
    while M > 0:
        i = M % 100
        M = (M-i)/100
        string = alphabet[i] + string
    return string

m = string2number(m)
print(m)

# Encrypted
c = power_mod(m, e, n)
print(f"Cipher text: {c}")

# Decrypted
decypher = power_mod(c, d, n)
decypher = number2string(decypher)
print(f"Decrypted message: {decypher}")