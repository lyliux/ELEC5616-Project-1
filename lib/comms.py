import hashlib
import struct
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dh import create_dh_key, calculate_dh_secret

from Crypto.Cipher import AES

from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string


# Traditional modes of operations for symmetric ciphers:
# ECB
# CBC
# CFB
# OFB
# CTR
# OpenPGP (a variant of CFB, RFC4880)

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True  # verbose
        self.shared_secret = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_secret.hex()))

    def send(self, data):
        if self.shared_secret:
            # Encrypt the message
            # Project TODO: Is XOR the best cipher here? Why not? Use a more secure cipher (from the pycryptodome library)
            data_to_send = aes_encrypt(self.shared_secret, data)
            # print("---------------")
            # print(self.shared_secret)
            # print(data)
            data_to_send = data_to_send + calculate_mac(self.shared_secret, data_to_send).encode()

            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(data_to_send)))
                print("Sending packet of length: {}".format(len(data_to_send)))
                print()
        else:
            data_to_send = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack("H", len(data_to_send))
        self.conn.sendall(pkt_len)
        self.conn.sendall(data_to_send)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        unpacked_contents = struct.unpack("H", pkt_len_packed)
        pkt_len = unpacked_contents[0]

        if self.shared_secret:
            encrypted_data_with_mac = self.conn.recv(pkt_len)
            ## check MAC
            MAC_INFO = encrypted_data_with_mac[-32:]
            encrypted_data = encrypted_data_with_mac[:-32]
            # print("---------------")
            # print(MAC_INFO)
            # print(encrypted_data)
            # print(self.shared_secret)
            # print(calculate_mac(self.shared_secret, encrypted_data).encode())
            if MAC_INFO != calculate_mac(self.shared_secret, encrypted_data).encode():
            # print("对对对对赌地")
                print("MAC verification error")
                return
            # Project TODO: as in send(), change the cipher here.
            # cipher = XOR(self.shared_secret)

            original_msg = aes_decrypt(self.shared_secret, encrypted_data)

            if self.verbose:
                print()
                print("Receiving message of length: {}".format(len(encrypted_data)))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original message: {}".format(original_msg))
                print()

        else:
            original_msg = self.conn.recv(pkt_len)

        return original_msg
    ## md5(concat share.screct key.hen()  + data ) as MAC

    def close(self):
        self.conn.close()


def aes_encrypt(key, plaintext):
    # 使用共享密钥作为 AES 密钥
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    # 添加填充
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext


def aes_decrypt(key, ciphertext):
    # 使用共享密钥作为 AES 密钥
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 删除填充
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def calculate_mac(share_secret, data):
    # 提取共享密钥的后5位
    last_five_bits = share_secret[-5:]
    # 将共享密钥的后5位与数据拼接
    combined_data = last_five_bits + data
    # 计算拼接后数据的 MD5 值作为 MAC
    mac = hashlib.md5(combined_data).hexdigest()
    return mac



# 65e35817eaaf7d9345226c9ef0972289d354c4875006114643af4b19f462471c
if __name__ == "__main__":
    tt = b'e\xe3X\x17\xea\xaf}\x93E"l\x9e\xf0\x97"\x89\xd3T\xc4\x87P\x06\x11FC\xafK\x19\xf4bG\x1c'
    data =    b"haha"
    print(aes_decrypt(tt, aes_encrypt(tt, data)))
    print(calculate_mac(tt, b"haha"))

    re =  data + calculate_mac(tt, data).encode()
    truncated_byte_string = re[-128:]
    print(re)


