from Crypto.PublicKey import RSA
from math import gcd
from rsa.prime import getprime
from Crypto.Util.number import long_to_bytes, bytes_to_long

def generate_and_save_public_key(file_path, key_size=1024):
    # Tạo cặp khóa RSA
    key = RSA.generate(key_size)
    
    # Xuất khóa công khai
    public_key = key.publickey().export_key()
    
    # Ghi khóa công khai vào tệp
    with open(file_path, 'wb') as f:
        f.write(public_key)
    
    print(f"Public key saved to {file_path}")
    return key



def get_pubkey(file):
    with open(file, 'rb') as f:
        key_data = f.read()
        public_key = RSA.import_key(key_data)
        N = public_key.n
        e = public_key.e
        return N, e

def test():
    # Lấy khóa công khai từ tệp pub.key
    pubkey_file = 'key.pub'
    N, e = get_pubkey(pubkey_file)
    
    print(f"N: {N}")
    print(f"e: {e}")
    
    # Nhập thông điệp từ bàn phím
    message = input("Nhập thông điệp cần mã hóa: ")

    # Chuyển thông điệp thành dạng byte
    message_bytes = message.encode('utf-8')

    # Chuyển thông điệp thành số nguyên
    m = bytes_to_long(message_bytes)

    # Mã hóa thông điệp bằng khóa công khai RSA
    ciphertext = pow(m, e, N)

    # In ra ciphertext
    print("Ciphertext:", ciphertext)
    
    # Ghi ciphertext vào tệp flag.enc
    with open('flag.enc', 'wb') as f:
        f.write(long_to_bytes(ciphertext))

# Sử dụng hàm để tạo và lưu khóa công khai
public_key_file = './key.pub'
key = generate_and_save_public_key(public_key_file)

# In ra N và e
print(f"N: {key.n}")
print(f"e: {key.e}")
# Gọi hàm test
test()
