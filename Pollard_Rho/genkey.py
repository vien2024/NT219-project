import rsa
from rsa import PublicKey, PrivateKey
from Crypto.Util.number import long_to_bytes, bytes_to_long

def generate_and_save_public_key(file_path, key_size=48):

    (public_key, private_key) = rsa.newkeys(key_size)
    
    # Xuất khóa công khai
    public_key_pem = public_key.save_pkcs1()
    
    # Ghi khóa công khai vào tệp
    with open(file_path, 'wb') as f:
        f.write(public_key_pem)
    
    print(f"Public key saved to {file_path}")
    return public_key, private_key

def get_pubkey(file):
    with open(file, 'rb') as f:
        key_data = f.read()
        public_key = rsa.PublicKey.load_pkcs1(key_data)
        N = public_key.n
        e = public_key.e
        return N, e

def test():
    # Lấy khóa công khai từ tệp pub.key
    pubkey_file = 'key.pub'
    N, e = get_pubkey(pubkey_file)
    
    print(f"N: {N}")
    print(f"e: {e}")
    
    choice = input("1.Nhập thông điệp\n2.Lấy thông điệp từ file\n")

    if choice == '1':
        message = input("Nhập thông điệp cần mã hóa: ")
        message_bytes = message.encode('utf-8')
        m = bytes_to_long(message_bytes)

    elif choice == '2':
        file_path = 'flag.txt'
        with open(file_path, 'rb') as f:
            message_bytes = f.read()
            m = bytes_to_long(message_bytes)
            
    else:
        print("Lựa chọn không hợp lệ")
        return

    # Mã hóa thông điệp bằng khóa công khai RSA
    ciphertext = pow(m, e, N)

    # In ra ciphertext
    print("Ciphertext:", ciphertext)
    
    # Ghi ciphertext vào tệp input.enc
    with open('input.enc', 'wb') as f:
        f.write(long_to_bytes(ciphertext))

# Sử dụng hàm để tạo và lưu khóa công khai
public_key_file = 'key.pub'
public_key, private_key = generate_and_save_public_key(public_key_file, key_size=48)

# In ra N và e của khóa công khai
print(f"N: {public_key.n}")
print(f"e: {public_key.e}")

# Gọi hàm test
test()
