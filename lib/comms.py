import struct
import secrets

from dh import create_dh_key, calculate_dh_secret
from .xor import XOR
from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string
from Crypto.Cipher import AES


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

            # encrypt using AES (block mode ___) (CFB or OFB mode???)

            # NOT FINISHED!
            # use nonce to avoid replay attacks
            # key = b'Sixteen byte key'
            # cipher = AES.new(key, AES.MODE_EAX)
            # nonce = cipher.nonce
            # data_to_send, tag = cipher.encrypt_and_digest(data)

            cipher = XOR(self.shared_secret)

            # Append MAC onto end of message, deliminate with hex byte 03
            before_encrypt = data
            before_encrypt = appendMac(before_encrypt, self.shared_secret)
            data_to_send = cipher.encrypt(before_encrypt)

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
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        unpacked_contents = struct.unpack("H", pkt_len_packed)
        pkt_len = unpacked_contents[0]

        if self.shared_secret:

            encrypted_data = self.conn.recv(pkt_len)
            # Project TODO: as in send(), change the cipher here.
            cipher = XOR(self.shared_secret)

            # Split original message from HMAC
            decoded_message = cipher.decrypt(encrypted_data)
            original_msg = b''
            hmac = b''
            deliminator = False
            SHA256_counter = 0

            for byte in reversed(decoded_message):
                byte = byte.to_bytes(1, "big")
                print(byte)
                print(SHA256_counter)

                # if byte == b'\x00':
                #     deliminator = True
                # elif deliminator:
                #     hmac += byte
                # else:
                #     original_msg += byte

                if SHA256_counter > 31:
                    original_msg = byte + original_msg
                else:
                    hmac = byte + hmac

                SHA256_counter += 1

            print()
            print("splitted")
            print(original_msg)
            print(hmac)

            # Perform MAC check on incoming message
            if not macCheck(original_msg, hmac, self.shared_secret):
                print()
                print("MAC Authentication failed")
                # return ""
            else:
                print()
                print("YIPPEPEEEEPEPEE!!!!")

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

    def close(self):
        self.conn.close()
