from math import gcd
from rsa.prime import getprime
from Crypto.Util.number import long_to_bytes, bytes_to_long


def test():
    # p, q = getprime(bits // 2), getprime(bits // 2)
    # n = p * q
    # print(f"p =, q= {q}, n={n}")
    # print(f"Factoring {n} ...")
    # d = pollard_rho(n)
    # print(f"Found d={d}")
    
    N = 143343629764599599571340769795746022959773706815376710221306973548295356389575483809287087003513534420142287331177408395999676493521275154222338864013268098588831299314720554803811006396609294045272707626514067702627093193625769456783888632484249859596420128320008429831394664161220635009309245617715069161179
    e = 65537
    # Thông điệp cần mã hóa
    message = "hello_pollard_rho"

    # Chuyển thông điệp thành dạng byte
    message_bytes = message.encode('utf-8')

    # Chuyển thông điệp thành số nguyên
    m = bytes_to_long(message_bytes)

    # Mã hóa thông điệp bằng khóa công khai RSA
    ciphertext = pow(m, e, N)

    print("Ciphertext:", long_to_bytes(ciphertext))


test()