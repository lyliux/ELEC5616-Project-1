import hashlib
import struct
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dh import create_dh_key, calculate_dh_secret

from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True  # verbose
        self.shared_secret = None
        self.nonce = b''  # acts both as a nonce and IV for AES OFB mode encryption
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

            # Gets nonce from receiver and stores in self.nonce
            self.receive_nonce()

            before_encrypt = data

            # Append MAC onto end of message, and encrypt using AES (iv appended)
            before_encrypt = appendMac(before_encrypt, self.shared_secret)

            # Encrypt the message using AES (block mode OFB)
            # form: iv/nonce(16 bytes) + ciphertext(plaintext + MAC(16 bytes))
            data_to_send = self.aes_encrypt(self.shared_secret, before_encrypt)

            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Original message + HMAC : {}".format(before_encrypt))
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
        # Send nonce to sending party if shared secret has been established
        if self.shared_secret:
            self.send_nonce()

        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        unpacked_contents = struct.unpack("H", pkt_len_packed)
        pkt_len = unpacked_contents[0]

        if self.shared_secret:
            encrypted_data = self.conn.recv(pkt_len)

            # Retrieve iv/nonce and split from encrypted data
            iv = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]

            # Decrypt the received data
            decoded_message = self.aes_decrypt(self.shared_secret, encrypted_data, iv)

            # Split original message from HMAC
            original_msg = b''
            hmac = b''
            SHA256_counter = 0

            for byte in reversed(decoded_message):
                byte = byte.to_bytes(1, "big")
                # 32 as each ascii character is 2 bytes
                if SHA256_counter >= 32:
                    original_msg = byte + original_msg
                else:
                    hmac = byte + hmac
                SHA256_counter += 1

            # Perform MAC check on incoming message
            if not macCheck(original_msg, hmac, self.shared_secret):
                print()
                print("MAC Authentication failed")
                return ""

            # Check the nonce that was sent matches the one that was included in
            # the message we just received
            if not self.nonce == iv:
                print()
                print("Nonce is different, attempted replay")
                return ""

            if self.verbose:
                print()
                print("Receiving message of length: {}".format(len(encrypted_data)))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original message + HMAC : {}".format(decoded_message))
                print("Original message: {}".format(original_msg))
                print()

        else:
            original_msg = self.conn.recv(pkt_len)

        return original_msg

    """
    Send randomly generated 16 byte nonce
    """
    def send_nonce(self):
        nonce = secrets.token_bytes(16)
        self.conn.sendall(nonce)
        self.nonce = nonce

    """
    Receive 16 byte nonce
    """
    def receive_nonce(self):
        nonce = self.conn.recv(16)
        self.nonce = nonce

    def close(self):
        self.conn.close()

    """
    Encrypt plaintext using AES (OFB mode) encryption  
    """
    def aes_encrypt(self, key, plaintext):
        # use shared key as key of AES
        backend = default_backend()

        # we use the nonce as the IV as well
        cipher = Cipher(algorithms.AES(key), modes.OFB(self.nonce), backend=backend)
        encryptor = cipher.encryptor()

        # add padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # finalise cipher text
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # add iv on the front
        ciphertext = self.nonce + ciphertext

        return ciphertext

    """
        Decrypt plaintext using AES (OFB mode) encryption  
    """
    def aes_decrypt(self, key, ciphertext, iv):
        # use shared key as key of AES
        backend = default_backend()

        # we use the nonce as the IV as well
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # delete padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext
